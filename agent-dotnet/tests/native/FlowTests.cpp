#include "Handoff.h"
#include "RegistrationContract.h"
#include <iostream>
#include <stdexcept>
#include <string>

static int checks = 0;
static void Check(bool value, const char* name) { if (!value) throw std::runtime_error(name); ++checks; }
template<class F> static void Reject(F action, const char* name) { try { action(); } catch (const std::exception&) { ++checks; return; } throw std::runtime_error(name); }
int main() {
    try {
        InstallConditions first; first.uiLevel = 5;
        Check(ShouldChoose(first), "first_install");
        for (int level : {0, 2, 3, 4}) { auto input = first; input.uiLevel = level; Check(!ShouldChoose(input), "unattended_bypass"); }
        auto input = first; input.installed = true; Check(!ShouldChoose(input), "maintenance");
        input = first; input.related = true; Check(!ShouldChoose(input), "upgrade");
        input = first; input.removing = true; Check(!ShouldChoose(input), "remove");
        input = first; input.repairing = true; Check(!ShouldChoose(input), "repair");
        input = first; input.completeArguments = true; Check(!ShouldChoose(input), "silent_contract");
        Check(SelectionResult(false, 0) == 1602, "cancel");
        Check(SelectionResult(false, 1) == 1603, "dialog_error");
        RequireNewBootstrap(false);
        Reject([&] { RequireNewBootstrap(true); }, "bootstrap_appeared_after_prepare_fails_closed");
        const auto prepared = PrepareStageInput(L"C:\\Synthetic\\bundle.snapshot", std::wstring(64, L'a'), L"https://sli.example.test/", std::wstring(64, L'b'));
        const auto second = PrepareStageInput(L"C:\\Synthetic\\bundle.snapshot", std::wstring(64, L'a'), L"https://sli.example.test/", std::wstring(64, L'b'));
        Check(prepared.transactionId.size() == 32 && prepared.transactionId != second.transactionId, "execute_generated_transactions");
        const auto wire = EncodeStageInput(prepared);
        const auto decoded = DecodeStageInput(wire);
        Check(decoded.transactionId == prepared.transactionId && decoded.snapshotPath == prepared.snapshotPath, "reference_roundtrip");
        Check(wire.find(std::wstring(43, L'g')) == std::wstring::npos && wire.find(L"token") == std::wstring::npos, "token_free_data");
        Reject([&] { DecodeStageInput(wire + L"|S-1-5-18"); }, "caller_sid_not_accepted");
        Reject([&] { DecodeStageInput(L"v0|path|data"); }, "unknown_transport");
        Reject([&] { PrepareStageInput(L"C:\\bad|path", std::wstring(64, L'a'), L"https://sli.example.test/", std::wstring(64, L'b')); }, "reference_injection");
        Reject([&] { PrepareStageInput(L"C:\\Synthetic\\bundle.snapshot", L"bad", L"https://sli.example.test/", std::wstring(64, L'b')); }, "bad_digest");
        std::cout << "PASS " << checks << " MSI flow/reference checks\n"; return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
