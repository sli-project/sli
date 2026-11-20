#include "Snapshot.h"
#include <aclapi.h>
#include <sddl.h>
#include <bcrypt.h>
#include <array>
#include <vector>
#include <stdexcept>
#include <memory>

namespace {
#ifdef REGISTRATION_TESTS
void (*snapshotOpenProbe)() = nullptr;
#endif
void Require(bool value) { if (!value) throw std::runtime_error("agent_snapshot_invalid"); }
struct Handle { HANDLE value = INVALID_HANDLE_VALUE; ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); } };
struct Local { void* value = nullptr; ~Local() { if (value) LocalFree(value); } };
struct Algorithm { BCRYPT_ALG_HANDLE value = nullptr; ~Algorithm() { if (value) BCryptCloseAlgorithmProvider(value, 0); } };
struct Hash { BCRYPT_HASH_HANDLE value = nullptr; ~Hash() { if (value) BCryptDestroyHash(value); } };
std::wstring Hex(const unsigned char* bytes, size_t length) {
    constexpr wchar_t hex[] = L"0123456789abcdef"; std::wstring text;
    for (size_t i = 0; i < length; ++i) { text += hex[bytes[i] >> 4]; text += hex[bytes[i] & 15]; }
    return text;
}
void Sid(const std::wstring& text, Local& sid) { Require(!text.empty() && ConvertStringSidToSidW(text.c_str(), &sid.value) != 0 && IsValidSid(sid.value)); }
bool SameText(const std::wstring& left, const std::wstring& right) { return CompareStringOrdinal(left.c_str(), -1, right.c_str(), -1, TRUE) == CSTR_EQUAL; }
void RegularMetadata(HANDLE handle) {
    BY_HANDLE_FILE_INFORMATION info{}; Require(GetFileInformationByHandle(handle, &info) != 0);
    Require(GetFileType(handle) == FILE_TYPE_DISK && info.nNumberOfLinks == 1
        && (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0);
    DWORD flags = 0; std::array<wchar_t, 32> filesystem{};
    Require(GetVolumeInformationByHandleW(handle, nullptr, 0, nullptr, nullptr, &flags, filesystem.data(), static_cast<DWORD>(filesystem.size())) != 0);
    Require((flags & FILE_PERSISTENT_ACLS) != 0 && SameText(filesystem.data(), L"NTFS"));
}
void ExactSnapshotSecurity(HANDLE handle, const std::wstring& userSid) {
    Local user; Sid(userSid, user); Require(!IsWellKnownSid(user.value, WinLocalSystemSid));
    PSID owner = nullptr; PACL dacl = nullptr; Local descriptor;
    Require(GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &dacl, nullptr, &descriptor.value) == ERROR_SUCCESS);
    Require(owner && EqualSid(owner, user.value) && dacl && IsValidAcl(dacl) && dacl->AceCount == 2);
    SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
    Require(GetSecurityDescriptorControl(descriptor.value, &control, &revision) != 0 && (control & SE_DACL_PROTECTED) != 0);
    bool foundUser = false, foundSystem = false;
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        void* raw = nullptr; Require(GetAce(dacl, i, &raw) != 0);
        const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        Require(ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && ace->Header.AceFlags == 0
            && ace->Header.AceSize >= sizeof(ACCESS_ALLOWED_ACE));
        auto aceSid = const_cast<DWORD*>(&ace->SidStart); Require(IsValidSid(aceSid) != 0);
        Require(ace->Header.AceSize == offsetof(ACCESS_ALLOWED_ACE, SidStart) + GetLengthSid(aceSid));
        if (EqualSid(aceSid, user.value)) { Require(!foundUser && ace->Mask == FILE_GENERIC_READ); foundUser = true; }
        else if (IsWellKnownSid(aceSid, WinLocalSystemSid)) { Require(!foundSystem && ace->Mask == FILE_ALL_ACCESS); foundSystem = true; }
        else throw std::runtime_error("agent_snapshot_invalid");
    }
    Require(foundUser && foundSystem);
}
void FinalPathMatches(HANDLE handle, const std::wstring& path) {
    std::array<wchar_t, 32768> buffer{};
    const auto size = GetFinalPathNameByHandleW(handle, buffer.data(), static_cast<DWORD>(buffer.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    Require(size > 4 && size < buffer.size());
    const std::wstring final(buffer.data(), size);
    Require(final.starts_with(L"\\\\?\\") && SameText(final.substr(4), path));
}
class LockedAncestors {
    std::vector<std::unique_ptr<Handle>> handles;
public:
    explicit LockedAncestors(const std::wstring& path) {
        std::vector<std::wstring> parents{path.substr(0, 3)};
        for (size_t i = 3; i < path.size(); ++i) if (path[i] == L'\\') parents.push_back(path.substr(0, i));
        for (const auto& parent : parents) {
            auto holder = std::make_unique<Handle>();
            // Directory data access is deliberate: sharing must constrain rename/reparse changes.
            holder->value = CreateFileW(parent.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
#ifdef REGISTRATION_TESTS
            if (holder->value == INVALID_HANDLE_VALUE) throw std::runtime_error("ancestor_open_" + std::to_string(handles.size()) + "_win32_" + std::to_string(GetLastError()));
#endif
            Require(holder->value != INVALID_HANDLE_VALUE);
            handles.push_back(std::move(holder));
            const auto handle = handles.back()->value;
            BY_HANDLE_FILE_INFORMATION info{};
            Require(GetFileType(handle) == FILE_TYPE_DISK && GetFileInformationByHandle(handle, &info) != 0
                && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 && (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0);
            FinalPathMatches(handle, parent);
        }
    }
};
std::string ReadBounded(HANDLE handle, unsigned* reads) {
    LARGE_INTEGER length{}; Require(GetFileSizeEx(handle, &length) != 0 && length.QuadPart > 0 && length.QuadPart <= 16384);
    std::string bytes(static_cast<size_t>(length.QuadPart), '\0'); DWORD read = 0;
    if (reads) ++*reads;
    Require(ReadFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) != 0 && read == bytes.size());
    return bytes;
}
}

std::wstring CurrentUserSid() {
    HANDLE raw = nullptr;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw)) {
        Require(GetLastError() == ERROR_NO_TOKEN);
        Require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw) != 0);
    }
    Handle token; token.value = raw; DWORD size = 0;
    GetTokenInformation(token.value, TokenUser, nullptr, 0, &size); Require(size > 0);
    std::vector<unsigned char> bytes(size); Require(GetTokenInformation(token.value, TokenUser, bytes.data(), size, &size) != 0);
    Local text; Require(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(bytes.data())->User.Sid, reinterpret_cast<LPWSTR*>(&text.value)) != 0);
    return static_cast<wchar_t*>(text.value);
}
std::wstring GenerateTransactionId() {
    std::array<unsigned char, 16> bytes{};
    Require(BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0);
    return Hex(bytes.data(), bytes.size());
}
std::wstring Sha256(std::string_view bytes) {
    Require(bytes.size() <= 16384); Algorithm algorithm;
    Require(BCryptOpenAlgorithmProvider(&algorithm.value, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0);
    DWORD length = 0, received = 0;
    Require(BCryptGetProperty(algorithm.value, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&length), sizeof(length), &received, 0) >= 0);
    std::vector<unsigned char> object(length); Hash hash;
    Require(BCryptCreateHash(algorithm.value, &hash.value, object.data(), length, nullptr, 0, 0) >= 0);
    Require(BCryptHashData(hash.value, reinterpret_cast<PUCHAR>(const_cast<char*>(bytes.data())), static_cast<ULONG>(bytes.size()), 0) >= 0);
    std::array<unsigned char, 32> digest{}; Require(BCryptFinishHash(hash.value, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0);
    return Hex(digest.data(), digest.size());
}
std::wstring CanonicalLocalPath(const std::wstring& path) {
    Require(path.size() >= 3 && path.size() < 32760 && path[1] == L':' && path[2] == L'\\'
        && ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')));
    Require(path.find(L':', 2) == std::wstring::npos && path.find_first_of(std::wstring{L'|', L'\0', L'\r', L'\n'}) == std::wstring::npos);
    Require(GetDriveTypeW(path.substr(0, 3).c_str()) == DRIVE_FIXED);
    std::array<wchar_t, 32768> full{}; const auto length = GetFullPathNameW(path.c_str(), static_cast<DWORD>(full.size()), full.data(), nullptr);
    Require(length > 0 && length < full.size());
    const std::wstring canonical(full.data(), length); Require(SameText(path, canonical));
    for (size_t i = 3; i < canonical.size(); ++i) if (canonical[i] == L'\\') {
        const auto attributes = GetFileAttributesW(canonical.substr(0, i).c_str());
        Require(attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0);
    }
    return canonical;
}
FileIdentity Identity(HANDLE handle) {
    BY_HANDLE_FILE_INFORMATION info{}; Require(GetFileInformationByHandle(handle, &info) != 0);
    return {info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow};
}
bool FileExists(const std::wstring& path) { return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES; }
UiSnapshot CreateUiSnapshot(const std::wstring& parent, std::string_view bytes) {
    Require(!bytes.empty() && bytes.size() <= 16384);
    UiSnapshot result; result.ownerSid = CurrentUserSid();
    Require(result.ownerSid != L"S-1-5-18");
    result.directory = CanonicalLocalPath(parent + L"\\sli-registration-" + GenerateTransactionId());
    Local directoryDescriptor;
    const auto directorySddl = L"O:" + result.ownerSid + L"D:P(A;;FA;;;" + result.ownerSid + L")(A;;FA;;;SY)";
    Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(directorySddl.c_str(), SDDL_REVISION_1, &directoryDescriptor.value, nullptr) != 0);
    SECURITY_ATTRIBUTES directorySecurity{sizeof(SECURITY_ATTRIBUTES), directoryDescriptor.value, FALSE};
    Require(CreateDirectoryW(result.directory.c_str(), &directorySecurity) != 0);
    { Handle directory; directory.value = CreateFileW(result.directory.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr); Require(directory.value != INVALID_HANDLE_VALUE); result.directoryIdentity = Identity(directory.value); }
    result.path = result.directory + L"\\bundle.snapshot";
    Local descriptor;
    const auto sddl = L"O:" + result.ownerSid + L"D:P(A;;FR;;;" + result.ownerSid + L")(A;;FA;;;SY)";
    Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor.value, nullptr) != 0);
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), descriptor.value, FALSE};
    Handle file;
    file.value = CreateFileW(result.path.c_str(), GENERIC_READ | GENERIC_WRITE | READ_CONTROL, 0, &security, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr);
    Require(file.value != INVALID_HANDLE_VALUE);
    DWORD written = 0; Require(WriteFile(file.value, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) != 0 && written == bytes.size());
    Require(FlushFileBuffers(file.value) != 0);
    ExactSnapshotSecurity(file.value, result.ownerSid); RegularMetadata(file.value); FinalPathMatches(file.value, result.path);
    result.identity = Identity(file.value); result.sha256 = Sha256(bytes); result.ownerReadOnly = true;
    return result;
}
std::string ReadVerifiedSnapshot(const std::wstring& path, const std::wstring& digest, const std::wstring& msiUserSid, unsigned* reads) {
    Local expected; Sid(msiUserSid, expected); Require(!IsWellKnownSid(expected.value, WinLocalSystemSid));
    Require(digest.size() == 64); for (auto c : digest) Require((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'));
    const auto canonical = CanonicalLocalPath(path); LockedAncestors ancestors(canonical); Handle file;
#ifdef REGISTRATION_TESTS
    if (snapshotOpenProbe) snapshotOpenProbe();
#endif
    file.value = CreateFileW(canonical.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
    Require(file.value != INVALID_HANDLE_VALUE);
    // Security and regular/single-link metadata are checked BY THIS HANDLE before the first ReadFile.
    ExactSnapshotSecurity(file.value, msiUserSid); RegularMetadata(file.value); FinalPathMatches(file.value, canonical);
    auto bytes = ReadBounded(file.value, reads);
    try { ExactSnapshotSecurity(file.value, msiUserSid); RegularMetadata(file.value);
        Require(Sha256(bytes) == digest);
    } catch (...) { SecureZeroMemory(bytes.data(),bytes.size()); throw; }
    return bytes;
}
void RemoveOwnedUiSnapshot(const UiSnapshot& snapshot) {
    Require(CurrentUserSid() == snapshot.ownerSid);
    Handle file; file.value = CreateFileW(snapshot.path.c_str(), DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES, 0, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    Require(file.value != INVALID_HANDLE_VALUE);
    ExactSnapshotSecurity(file.value, snapshot.ownerSid); RegularMetadata(file.value); Require(Identity(file.value) == snapshot.identity);
    FILE_DISPOSITION_INFO disposition{TRUE}; Require(SetFileInformationByHandle(file.value, FileDispositionInfo, &disposition, sizeof(disposition)) != 0);
    CloseHandle(file.value); file.value = INVALID_HANDLE_VALUE;
    Handle directory; directory.value = CreateFileW(snapshot.directory.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    Require(directory.value != INVALID_HANDLE_VALUE && Identity(directory.value) == snapshot.directoryIdentity);
    CloseHandle(directory.value); directory.value = INVALID_HANDLE_VALUE;
    Require(RemoveDirectoryW(snapshot.directory.c_str()) != 0);
}
std::string ReadOriginalAsUiUser(const std::wstring& path) {
    Require(CurrentUserSid() != L"S-1-5-18"); Handle file;
    file.value = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    Require(file.value != INVALID_HANDLE_VALUE); RegularMetadata(file.value);
    return ReadBounded(file.value, nullptr);
}
#ifdef REGISTRATION_TESTS
void SetSnapshotOpenProbe(void (*probe)()) { snapshotOpenProbe = probe; }
#endif
