#include "BootstrapStage.h"
#include "Snapshot.h"
#include "RegistrationContract.h"
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <array>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace {
void Require(bool value) { if (!value) throw std::runtime_error("agent_stage_invalid"); }
struct Handle { HANDLE value = INVALID_HANDLE_VALUE; ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); } };
struct Local { void* value = nullptr; ~Local() { if (value) LocalFree(value); } };
std::wstring FixtureSid() {
#ifdef REGISTRATION_TESTS
    return CurrentUserSid();
#else
    return L"";
#endif
}
std::wstring Owner() { const auto fixture = FixtureSid(); return fixture.empty() ? L"S-1-5-18" : fixture; }
std::wstring Policy() {
    const auto fixture = FixtureSid();
    return L"O:" + Owner() + L"D:P(A;;FA;;;SY)(A;;FA;;;BA)" + (fixture.empty() ? L"" : L"(A;;FA;;;" + fixture + L")");
}
void Transaction(const std::wstring& value) {
    Require(value.size() == 32); for (auto c : value) Require((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'));
}
void Security(HANDLE handle, bool exact) {
    PSID owner = nullptr; PACL dacl = nullptr; Local descriptor;
    Require(GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &dacl, nullptr, &descriptor.value) == ERROR_SUCCESS);
    Local expected; Require(ConvertStringSidToSidW(Owner().c_str(), &expected.value) != 0);
    Require(owner && (EqualSid(owner, expected.value) || (!exact && IsWellKnownSid(owner, WinBuiltinAdministratorsSid))) && dacl && IsValidAcl(dacl));
    SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
    Require(GetSecurityDescriptorControl(descriptor.value, &control, &revision) != 0 && (control & SE_DACL_PROTECTED) != 0);
    const auto fixture = FixtureSid();
    if (exact) Require(dacl->AceCount == (fixture.empty() ? 2u : 3u));
    bool system = false, administrators = false, testOwner = false;
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        void* raw = nullptr; Require(GetAce(dacl, i, &raw) != 0);
        const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        Require(ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && (!exact || ace->Header.AceFlags == 0));
        auto sid = const_cast<DWORD*>(&ace->SidStart); Require(IsValidSid(sid));
        if (IsWellKnownSid(sid, WinLocalSystemSid)) { system = true; Require(ace->Mask == FILE_ALL_ACCESS); }
        else if (IsWellKnownSid(sid, WinBuiltinAdministratorsSid)) { administrators = true; Require(ace->Mask == FILE_ALL_ACCESS); }
        else if (!fixture.empty() && EqualSid(sid, expected.value)) { testOwner = true; Require(ace->Mask == FILE_ALL_ACCESS); }
        else Require(!exact && (ace->Mask & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER)) == 0);
    }
    Require(system && administrators && (fixture.empty() || testOwner));
}
void OpenDirectory(const std::wstring& path, Handle& handle, bool exact) {
    CanonicalLocalPath(path);
    handle.value = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
    Require(handle.value != INVALID_HANDLE_VALUE);
    BY_HANDLE_FILE_INFORMATION info{}; Require(GetFileInformationByHandle(handle.value, &info) != 0
        && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 && (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0);
    Security(handle.value, exact);
}
void CreateDirectoryPrivate(const std::wstring& path) {
    Local descriptor; Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(Policy().c_str(), SDDL_REVISION_1, &descriptor.value, nullptr) != 0);
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor.value, FALSE};
    Require(CreateDirectoryW(path.c_str(), &attributes) != 0);
}
void EnsureBase(const std::wstring& base, Handle& lockedBase) {
    CanonicalLocalPath(base);
#ifndef REGISTRATION_TESTS
    Require(CurrentUserSid() == L"S-1-5-18");
    const auto parent = base.substr(0, base.find_last_of(L'\\'));
    Handle protectedParent; OpenDirectory(parent, protectedParent, false);
#endif
    if (!FileExists(base)) CreateDirectoryPrivate(base);
    OpenDirectory(base, lockedBase, true);
}
void NewFile(const std::wstring& path, std::string_view bytes) {
    Require(bytes.size() <= 16384); Local descriptor;
    Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(Policy().c_str(), SDDL_REVISION_1, &descriptor.value, nullptr) != 0);
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor.value, FALSE}; Handle file;
    file.value = CreateFileW(path.c_str(), GENERIC_WRITE | READ_CONTROL, 0, &attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
    Require(file.value != INVALID_HANDLE_VALUE); Security(file.value, true);
    DWORD written = 0; Require(WriteFile(file.value, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) != 0 && written == bytes.size());
    Require(FlushFileBuffers(file.value) != 0);
}
void OpenOwnedFile(const std::wstring& path, Handle& file, DWORD access) {
    file.value = CreateFileW(path.c_str(), access | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
    Require(file.value != INVALID_HANDLE_VALUE); Security(file.value, true);
    BY_HANDLE_FILE_INFORMATION info{}; Require(GetFileInformationByHandle(file.value, &info) != 0 && info.nNumberOfLinks == 1
        && (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0);
}
std::string ReceiptText(const std::wstring& path) {
    Handle file; OpenOwnedFile(path, file, GENERIC_READ);
    LARGE_INTEGER length{}; Require(GetFileSizeEx(file.value, &length) != 0 && length.QuadPart > 0 && length.QuadPart <= 512);
    std::string result(static_cast<size_t>(length.QuadPart), '\0'); DWORD read = 0;
    Require(ReadFile(file.value, result.data(), static_cast<DWORD>(result.size()), &read, nullptr) != 0 && read == result.size());
    return result;
}
void DeleteOwned(const std::wstring& path, const FileIdentity* expected = nullptr) {
    Handle file; OpenOwnedFile(path, file, DELETE | FILE_READ_ATTRIBUTES);
    if (expected) Require(Identity(file.value) == *expected);
    FILE_DISPOSITION_INFO disposition{TRUE}; Require(SetFileInformationByHandle(file.value, FileDispositionInfo, &disposition, sizeof(disposition)) != 0);
}
StageReceipt StageAt(const std::wstring& base, const std::wstring& transaction, std::string_view enrollment) {
    Transaction(transaction); Require(!enrollment.empty() && enrollment.size() <= 8192);
    Handle root; EnsureBase(base, root);
    const auto directory = base + L"\\" + transaction;
    CreateDirectoryPrivate(directory);
    const auto temporary = directory + L"\\enrollment.tmp", destination = directory + L"\\enrollment.json", receipt = directory + L"\\receipt.txt";
    bool published = false;
    try {
        NewFile(temporary, enrollment);
        Require(MoveFileExW(temporary.c_str(), destination.c_str(), MOVEFILE_WRITE_THROUGH) != 0); published = true;
        FileIdentity identity;
        { Handle file; OpenOwnedFile(destination, file, FILE_READ_ATTRIBUTES); identity = Identity(file.value); }
        std::ostringstream text;
        const auto digest = Sha256(enrollment);
        text << "SLI1\n" << EncodeUtf8(transaction) << "\n" << identity.volume << ' ' << identity.high << ' ' << identity.low
            << "\n" << EncodeUtf8(digest) << "\n";
        NewFile(receipt, text.str());
        return {transaction, destination};
    } catch (...) {
        try { if (FileExists(receipt)) DeleteOwned(receipt); if (published) DeleteOwned(destination); else if (FileExists(temporary)) DeleteOwned(temporary); RemoveDirectoryW(directory.c_str()); } catch (...) {}
        throw;
    }
}
void RollbackAt(const std::wstring& base, const std::wstring& transaction) {
    Transaction(transaction); Handle root; OpenDirectory(base, root, true);
    const auto directory = base + L"\\" + transaction; Handle locked; OpenDirectory(directory, locked, true);
    const auto receipt = directory + L"\\receipt.txt";
    Require(!FileExists(directory + L"\\committed.txt"));
    std::istringstream text(ReceiptText(receipt)); std::string magic, id; FileIdentity identity;
    std::getline(text, magic); std::getline(text, id);
    Require(magic == "SLI1" && id == EncodeUtf8(transaction));
    Require(static_cast<bool>(text >> identity.volume >> identity.high >> identity.low));
    if (FileExists(directory + L"\\enrollment.json")) DeleteOwned(directory + L"\\enrollment.json", &identity);
    DeleteOwned(receipt);
    CloseHandle(locked.value); locked.value = INVALID_HANDLE_VALUE;
    Require(RemoveDirectoryW(directory.c_str()) != 0);
}
void CommitAt(const std::wstring& base, const std::wstring& transaction) {
    Transaction(transaction); Handle root; OpenDirectory(base, root, true);
    const auto directory = base + L"\\" + transaction; Handle locked; OpenDirectory(directory, locked, true);
    Require(FileExists(directory + L"\\receipt.txt"));
    NewFile(directory + L"\\committed.txt", "SLI1 committed; enrollment retained for existing runtime\n");
}

std::vector<std::wstring> Children(const std::wstring& directory) {
    WIN32_FIND_DATAW entry{};
    const auto search = FindFirstFileW((directory + L"\\*").c_str(), &entry);
    if (search == INVALID_HANDLE_VALUE) {
        Require(GetLastError() == ERROR_FILE_NOT_FOUND);
        return {};
    }
    std::vector<std::wstring> names;
    do {
        const std::wstring name = entry.cFileName;
        if (name != L"." && name != L"..") names.push_back(name);
    } while (FindNextFileW(search, &entry));
    const auto error = GetLastError();
    FindClose(search);
    Require(error == ERROR_NO_MORE_FILES);
    return names;
}

void DeleteTree(const std::wstring& path) {
    const auto attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        const auto error = GetLastError();
        Require(error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND);
        return;
    }
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        {
            Handle locked;
            locked.value = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            BY_HANDLE_FILE_INFORMATION info{};
            Require(locked.value != INVALID_HANDLE_VALUE && GetFileInformationByHandle(locked.value, &info)
                && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY));
            if (!(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                for (const auto& name : Children(path)) DeleteTree(path + L"\\" + name);
        }
        Require(RemoveDirectoryW(path.c_str()) != 0);
    } else {
        Require(DeleteFileW(path.c_str()) != 0);
    }
}

void CleanState(const std::wstring& root, const std::wstring& name, bool purgeQueue) {
    const auto state = root + L"\\" + name;
    const auto queue = state + L"\\queue";
    const auto attributes = GetFileAttributesW(state.c_str());
    if (!purgeQueue && attributes != INVALID_FILE_ATTRIBUTES
        && (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == FILE_ATTRIBUTE_DIRECTORY) {
        const auto queueAttributes = GetFileAttributesW(queue.c_str());
        if (queueAttributes != INVALID_FILE_ATTRIBUTES
            && (queueAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == FILE_ATTRIBUTE_DIRECTORY) {
            const auto retained = root + L"\\retained-queue-" + name;
            if (GetFileAttributesW(retained.c_str()) != INVALID_FILE_ATTRIBUTES) {
                // Keep both queues if a previous uninstall already retained one.
                const auto unique = retained + L"-" + std::to_wstring(GetTickCount64());
                Require(MoveFileExW(queue.c_str(), unique.c_str(), MOVEFILE_WRITE_THROUGH) != 0);
            } else {
                Require(MoveFileExW(queue.c_str(), retained.c_str(), MOVEFILE_WRITE_THROUGH) != 0);
            }
        }
    }
    DeleteTree(state);
}
void CleanAt(const std::wstring& root, bool purgeQueue) {
    Handle lockedRoot;
    OpenDirectory(root, lockedRoot, false);
    for (const auto& name : Children(root)) {
        if (name == L"state" || name.starts_with(L"previous-")) CleanState(root, name, purgeQueue);
        else if (name == L"registration" || name == L"install.lock" || name.starts_with(L"install-")
            || (name.starts_with(L"ca-") && name.ends_with(L".crt"))
            || (purgeQueue && name.starts_with(L"retained-queue-"))) DeleteTree(root + L"\\" + name);
    }
}
}

std::wstring ProductionStageBase() {
    PWSTR path = nullptr; Require(SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &path)));
    const std::wstring result = std::wstring(path) + L"\\SLI\\AgentNet\\registration"; CoTaskMemFree(path); return result;
}
StageReceipt StageProduction(const std::wstring& transaction, std::string_view enrollment) { return StageAt(ProductionStageBase(), transaction, enrollment); }
void RollbackProduction(const std::wstring& transaction) { RollbackAt(ProductionStageBase(), transaction); }
void CommitProduction(const std::wstring& transaction) { CommitAt(ProductionStageBase(), transaction); }
void CleanProductionState(bool purgeQueue) {
    Require(CurrentUserSid() == L"S-1-5-18");
    const auto stage = ProductionStageBase();
    const auto root = stage.substr(0, stage.find_last_of(L'\\'));
    if (GetFileAttributesW(root.c_str()) != INVALID_FILE_ATTRIBUTES) {
        const auto parent = root.substr(0, root.find_last_of(L'\\'));
        Handle lockedParent;
        lockedParent.value = CreateFileW(parent.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        BY_HANDLE_FILE_INFORMATION info{};
        Require(lockedParent.value != INVALID_HANDLE_VALUE && GetFileInformationByHandle(lockedParent.value, &info)
            && (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == FILE_ATTRIBUTE_DIRECTORY);
        CleanAt(root, purgeQueue);
    } else {
        const auto error = GetLastError();
        Require(error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND);
    }
    HKEY key = nullptr;
    const auto opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\SLI\\AgentNet", 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &key);
    Require(opened == ERROR_SUCCESS || opened == ERROR_FILE_NOT_FOUND);
    if (key) {
        bool cleared = true;
        for (const auto name : {L"ServerUrl", L"CaBundle", L"CaFingerprint", L"TokenFile", L"InstanceName", L"EnrollmentToken", L"StateDirectory"}) {
            const auto result = RegDeleteValueW(key, name);
            cleared = cleared && (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND);
        }
        RegCloseKey(key);
        Require(cleared);
    }
}
#ifdef REGISTRATION_TESTS
StageReceipt StageFixture(const std::wstring& base, const std::wstring& transaction, std::string_view enrollment) { return StageAt(base, transaction, enrollment); }
void RollbackFixture(const std::wstring& base, const std::wstring& transaction) { RollbackAt(base, transaction); }
void CommitFixture(const std::wstring& base, const std::wstring& transaction) { CommitAt(base, transaction); }
void CleanFixture(const std::wstring& base, bool purgeQueue) { CleanAt(base, purgeQueue); }
#endif
