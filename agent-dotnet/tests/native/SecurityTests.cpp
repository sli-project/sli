#include "Snapshot.h"
#include "BootstrapStage.h"
#include "RegistrationContract.h"
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <winioctl.h>
#include <shlobj.h>
#include <fstream>
#include <vector>
#include <cstring>
#include <iostream>
#include <string>
#include <stdexcept>

static int checks = 0;
static std::wstring swappingDirectory, savedDirectory;
static void Check(bool value, const char* name) { if (!value) throw std::runtime_error(name); ++checks; }
template<class F> static void Reject(F action, const char* name) { try { action(); } catch (const std::exception&) { ++checks; return; } throw std::runtime_error(name); }
static void SwapAncestorAtOpen() {
    const auto moved = MoveFileExW(swappingDirectory.c_str(), savedDirectory.c_str(), 0);
    if (moved) Check(MoveFileExW(savedDirectory.c_str(), swappingDirectory.c_str(), 0) != 0, "fixture_restore_ancestor");
    Check(!moved, "ancestor_swap_denied_before_open");
}
static void SetDacl(const std::wstring& path, const std::wstring& sddl) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    Check(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr) != 0, "fixture_descriptor");
    PACL dacl = nullptr; BOOL present = FALSE, defaulted = FALSE;
    GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted);
    const auto result = SetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr);
    LocalFree(descriptor); Check(result == ERROR_SUCCESS, "fixture_dacl");
}
static void CheckUiParent(const std::wstring& path, const std::wstring& sid) {
    const auto handle = CreateFileW(path.c_str(), READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    Check(handle != INVALID_HANDLE_VALUE, "ui_parent_open");
    PSID owner = nullptr, expected = nullptr; PACL dacl = nullptr; PSECURITY_DESCRIPTOR descriptor = nullptr;
    Check(ConvertStringSidToSidW(sid.c_str(), &expected) != 0, "ui_parent_expected_sid");
    const auto status = GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &dacl, nullptr, &descriptor);
    Check(status == ERROR_SUCCESS && owner && EqualSid(owner, expected), "ui_parent_actual_owner");
    SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
    Check(GetSecurityDescriptorControl(descriptor, &control, &revision) != 0 && (control & SE_DACL_PROTECTED) && dacl && dacl->AceCount == 2, "ui_parent_protected_two_aces");
    for (DWORD i = 0; i < dacl->AceCount; ++i) { void* raw = nullptr; Check(GetAce(dacl, i, &raw) != 0, "ui_parent_ace"); const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        Check(ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && ace->Header.AceFlags == 0 && ace->Mask == FILE_ALL_ACCESS
            && (EqualSid(const_cast<DWORD*>(&ace->SidStart), expected) || IsWellKnownSid(const_cast<DWORD*>(&ace->SidStart), WinLocalSystemSid)), "ui_parent_exact_allow_policy"); }
    LocalFree(expected); LocalFree(descriptor); CloseHandle(handle);
}
static void WriteSource(const std::wstring& path,const std::string& bytes) {
    const auto handle=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    Check(handle!=INVALID_HANDLE_VALUE,"source_fixture_open");DWORD written=0;
    Check(WriteFile(handle,bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr)!=0&&written==bytes.size(),"source_fixture_write");CloseHandle(handle);
}
static void Junction(const std::wstring& link,const std::wstring& target) {
    Check(CreateDirectoryW(link.c_str(),nullptr)!=0,"junction_fixture_directory");
    const auto handle=CreateFileW(link.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    Check(handle!=INVALID_HANDLE_VALUE,"junction_fixture_open");
    const auto substitute=L"\\??\\"+target;
    const auto pathChars=substitute.size()+1+target.size()+1;
    std::vector<unsigned char> buffer(16+pathChars*sizeof(wchar_t),0);
    auto words=reinterpret_cast<WORD*>(buffer.data());
    *reinterpret_cast<DWORD*>(buffer.data())=IO_REPARSE_TAG_MOUNT_POINT;
    words[2]=static_cast<WORD>(8+pathChars*sizeof(wchar_t));
    words[4]=0;words[5]=static_cast<WORD>(substitute.size()*sizeof(wchar_t));
    words[6]=static_cast<WORD>((substitute.size()+1)*sizeof(wchar_t));words[7]=static_cast<WORD>(target.size()*sizeof(wchar_t));
    std::memcpy(buffer.data()+16,substitute.c_str(),(substitute.size()+1)*sizeof(wchar_t));
    std::memcpy(buffer.data()+16+(substitute.size()+1)*sizeof(wchar_t),target.c_str(),(target.size()+1)*sizeof(wchar_t));
    DWORD returned=0;const auto ok=DeviceIoControl(handle,FSCTL_SET_REPARSE_POINT,buffer.data(),static_cast<DWORD>(buffer.size()),nullptr,0,&returned,nullptr);CloseHandle(handle);
    Check(ok!=0,"junction_fixture_set");
}
int wmain(int argc, wchar_t** argv) {
    try {
        if (argc != 2) throw std::runtime_error("fixture_root_required");
        const std::wstring root = argv[1], sid = CurrentUserSid();
        Check(!IsUserAnAdmin(), "normal_user_fixture_not_elevated");
        const std::string original = "synthetic-input-abc";
        const auto roundtrip = CreateUiSnapshot(root, original);
        CheckUiParent(roundtrip.directory, sid);
        Check(roundtrip.ownerReadOnly && roundtrip.ownerSid == sid, "roundtrip_owner_and_readonly_file");
        Check(ReadVerifiedSnapshot(roundtrip.path, roundtrip.sha256, sid) == original, "roundtrip_exact_bytes");
        RemoveOwnedUiSnapshot(roundtrip);
        Check(!FileExists(roundtrip.path) && !FileExists(roundtrip.directory), "normal_user_create_remove_roundtrip");
        const auto sourcePath=root+L"\\original-"+GenerateTransactionId()+L".json";
        WriteSource(sourcePath,original);
        const auto captured=ReadOriginalAsUiUser(sourcePath);
        const auto snapshot = CreateUiSnapshot(root, captured);
        unsigned reads = 0;
        Check(ReadVerifiedSnapshot(snapshot.path, snapshot.sha256, sid, &reads) == original && reads == 1, "exact_snapshot");
        Check(snapshot.ownerReadOnly, "narrow_final_policy");
        swappingDirectory = snapshot.directory; savedDirectory = snapshot.directory + L"-swapped";
        SetSnapshotOpenProbe(SwapAncestorAtOpen);
        Check(ReadVerifiedSnapshot(snapshot.path, snapshot.sha256, sid) == original, "locked_ancestors_read_same_bytes");
        SetSnapshotOpenProbe(nullptr);
        // Original source changes do not affect the already copied snapshot.
        WriteSource(sourcePath,"different original");
        Check(ReadVerifiedSnapshot(snapshot.path, snapshot.sha256, sid) == original, "snapshot_independent_of_original");
        Reject([&] { ReadVerifiedSnapshot(snapshot.path, std::wstring(64, L'0'), sid); }, "digest_mismatch");
        reads = 0;
        Reject([&] { ReadVerifiedSnapshot(snapshot.path, snapshot.sha256, L"S-1-1-0", &reads); }, "wrong_owner");
        Check(reads == 0, "wrong_owner_before_read");
        Reject([&] { ReadVerifiedSnapshot(snapshot.path, snapshot.sha256, L"", &reads); }, "missing_sid");
        Check(reads == 0, "missing_sid_before_read");
        for (const auto& path : {L"relative.json", L"\\\\unreachable.invalid\\share\\x", L"\\\\?\\C:\\x", L"\\\\.\\C:\\x", L"C:\\x:stream"}) {
            Reject([&] { ReadVerifiedSnapshot(path, snapshot.sha256, sid, &reads); }, "invalid_locator");
            Check(reads == 0, "invalid_locator_before_read");
        }
        SetDacl(snapshot.path, L"D:P(A;;FR;;;" + sid + L")(A;;FA;;;SY)(A;;FR;;;WD)");
        reads = 0;
        Reject([&] { ReadVerifiedSnapshot(snapshot.path, snapshot.sha256, sid, &reads); }, "extra_ace");
        Check(reads == 0, "extra_ace_before_read");
        SetDacl(snapshot.path, L"D:P(A;;FA;;;" + sid + L")(A;;FA;;;SY)");
        Reject([&] { ReadVerifiedSnapshot(snapshot.path, snapshot.sha256, sid, &reads); }, "owner_write_mask_rejected");
        Check(reads == 0, "wrong_mask_before_read");
        SetDacl(snapshot.path,L"D:P(A;;FA;;;SY)");
        Reject([&]{ReadVerifiedSnapshot(snapshot.path,snapshot.sha256,sid,&reads);},"system_only_dacl");
        Check(reads==0,"system_only_before_read");
        SetDacl(snapshot.path, L"D:P(A;;FR;;;" + sid + L")(A;;FA;;;SY)");
        const auto junction=root+L"\\junction-"+GenerateTransactionId();
        Junction(junction,snapshot.directory);
        Reject([&]{ReadVerifiedSnapshot(junction+L"\\bundle.snapshot",snapshot.sha256,sid,&reads);},"reparse_parent");
        Check(reads==0,"reparse_before_read");Check(RemoveDirectoryW(junction.c_str())!=0,"remove_junction_only");
        const auto link = snapshot.directory + L"\\snapshot-link.json";
        SetDacl(snapshot.path, L"D:P(A;;FA;;;" + sid + L")(A;;FA;;;SY)");
        if (CreateHardLinkW(link.c_str(), snapshot.path.c_str(), nullptr)) {
            SetDacl(snapshot.path, L"D:P(A;;FR;;;" + sid + L")(A;;FA;;;SY)");
            Reject([&] { ReadVerifiedSnapshot(snapshot.path, snapshot.sha256, sid, &reads); }, "multiple_links");
            Check(reads == 0, "links_before_read"); Check(DeleteFileW(link.c_str()) != 0, "remove_fixture_link");
        } else throw std::runtime_error("hardlink_fixture_unavailable");
        SetDacl(snapshot.path, L"D:P(A;;FA;;;" + sid + L")(A;;FA;;;SY)");
        const auto writer = CreateFileW(snapshot.path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        Check(writer != INVALID_HANDLE_VALUE, "fixture_writer");
        DWORD written = 0; Check(WriteFile(writer, "changed", 7, &written, nullptr) != 0, "fixture_snapshot_changed"); CloseHandle(writer);
        SetDacl(snapshot.path, L"D:P(A;;FR;;;" + sid + L")(A;;FA;;;SY)");
        Reject([&] { ReadVerifiedSnapshot(snapshot.path, snapshot.sha256, sid); }, "changed_snapshot_rejected");
        RemoveOwnedUiSnapshot(snapshot);
        SetDacl(sourcePath,L"D:P(A;;FA;;;"+sid+L")(A;;FA;;;SY)");Check(DeleteFileW(sourcePath.c_str())!=0,"source_fixture_removed");

#ifndef SNAPSHOT_ONLY
        const auto stageRoot = root + L"\\stage-fixture";
        const auto tx = GenerateTransactionId();
        const auto receipt = StageFixture(stageRoot, tx, "{\"synthetic\":true}");
        Check(receipt.transactionId == tx && FileExists(receipt.enrollmentPath), "stage_published");
        {std::ifstream file(stageRoot+L"\\"+tx+L"\\receipt.txt",std::ios::binary);std::string text((std::istreambuf_iterator<char>(file)),{});Check(text.find("synthetic")==std::string::npos,"receipt_has_no_input_content");}
        Reject([&] { StageFixture(stageRoot, tx, "replacement"); }, "no_overwrite");
        Reject([&] { RollbackFixture(stageRoot, GenerateTransactionId()); }, "unowned_transaction_rejected");
        Check(FileExists(receipt.enrollmentPath), "other_transaction_preserved");
        RollbackFixture(stageRoot, tx);
        Check(!FileExists(receipt.enrollmentPath), "owned_rollback");
        Reject([&] { StageFixture(stageRoot, L"..\\other", "x"); }, "transaction_path_injection");
        const auto next = StageFixture(stageRoot, GenerateTransactionId(), "{\"pending\":true}");
        CommitFixture(stageRoot, next.transactionId);
        Check(FileExists(next.enrollmentPath), "commit_retains_pending_input");
        Reject([&] { RollbackFixture(stageRoot, next.transactionId); }, "committed_not_removed");

        const auto state = stageRoot + L"\\state";
        const auto external = root + L"\\external-" + GenerateTransactionId();
        Check(CreateDirectoryW(state.c_str(), nullptr) != 0, "uninstall_state_fixture");
        Check(CreateDirectoryW((state + L"\\queue").c_str(), nullptr) != 0, "uninstall_queue_fixture");
        Check(CreateDirectoryW(external.c_str(), nullptr) != 0, "uninstall_external_fixture");
        WriteSource(state + L"\\identity-key.json", "synthetic protected key");
        WriteSource(state + L"\\queue\\packet.json", "synthetic packet");
        WriteSource(external + L"\\untouched.txt", "synthetic external data");
        Junction(state + L"\\junction", external);
        CleanFixture(stageRoot, false);
        Check(!FileExists(state), "uninstall_removes_identity_and_state");
        Check(FileExists(stageRoot + L"\\retained-queue-state\\packet.json"), "uninstall_retains_queue_by_default");
        Check(FileExists(external + L"\\untouched.txt"), "uninstall_does_not_follow_junction");
        CleanFixture(stageRoot, true);
        Check(!FileExists(stageRoot + L"\\retained-queue-state"), "uninstall_explicitly_purges_retained_queue");
#endif
        std::cout << "PASS " << checks << " snapshot/staging checks in synthetic fixture policy\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << "; Win32=" << GetLastError() << '\n'; return 1;
    }
}
