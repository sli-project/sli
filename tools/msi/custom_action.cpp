// SPDX-License-Identifier: Apache-2.0
// Public properties only. Tokens are never read by Windows Installer.
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <msiquery.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <utility>
#include <initializer_list>

static std::wstring property(MSIHANDLE session, const wchar_t* name) {
    DWORD length = 0;
    wchar_t empty = 0;
    UINT status = MsiGetPropertyW(session, name, &empty, &length);
    if (status != ERROR_MORE_DATA && status != ERROR_SUCCESS) throw std::runtime_error("property");
    if (length > 30000) throw std::runtime_error("property");
    std::vector<wchar_t> value(length + 1);
    ++length;
    if (MsiGetPropertyW(session, name, value.data(), &length) != ERROR_SUCCESS) throw std::runtime_error("property");
    return std::wstring(value.data(), length);
}

static std::wstring hex(const std::wstring& value) {
    if (value.empty()) return L"-";
    const wchar_t* digits = L"0123456789abcdef";
    std::wstring result;
    for (wchar_t ch : value) {
        // Byte order must match Python's utf-16le, including surrogate pairs.
        for (unsigned byte : {static_cast<unsigned>(ch) & 255, static_cast<unsigned>(ch) >> 8}) {
            result += digits[byte >> 4]; result += digits[byte & 15];
        }
    }
    return result;
}

static UINT error(MSIHANDLE session, const wchar_t* message) {
    MSIHANDLE record = MsiCreateRecord(1);
    MsiRecordSetStringW(record, 0, L"SLI Agent: [1]");
    MsiRecordSetStringW(record, 1, message);
    MsiProcessMessage(session, INSTALLMESSAGE_ERROR, record);
    MsiCloseHandle(record);
    return ERROR_INSTALL_FAILURE;
}

extern "C" __declspec(dllexport) UINT __stdcall PrepareAgent(MSIHANDLE session) {
    try {
        PWSTR folder = nullptr;
        if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, nullptr, &folder)))
            return error(session, L"Cannot locate the machine Program Files directory.");
        std::wstring root = std::wstring(folder) + L"\\SLI\\Agent\\";
        CoTaskMemFree(folder);
        // Fix the directory even if an external transform supplied INSTALLFOLDER.
        if (MsiSetTargetPathW(session, L"INSTALLFOLDER", root.c_str()) != ERROR_SUCCESS)
            throw std::runtime_error("directory");
        if (property(session, L"Installed").empty() && property(session, L"WIX_UPGRADE_DETECTED").empty()) {
            SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (!manager) return error(session, L"Cannot read the service registry. Use an elevated administrator or SYSTEM installation job.");
            SC_HANDLE existing = OpenServiceW(manager, L"SLIAgent", SERVICE_QUERY_STATUS);
            DWORD status = existing ? ERROR_SUCCESS : GetLastError();
            if (existing) CloseServiceHandle(existing);
            CloseServiceHandle(manager);
            if (status != ERROR_SERVICE_DOES_NOT_EXIST)
                return error(session, L"A service named SLIAgent already exists or cannot be inspected. Resolve the pilot installation before installing this MSI; existing identity will not be overwritten.");
        } else {
            auto account = property(session, L"STORED_SERVICE_ACCOUNT");
            if (!account.empty()) MsiSetPropertyW(session, L"SERVICE_ACCOUNT", account.c_str());
        }
        std::wstring command = L"\"" + root + L"python.exe\" -I -B -m sli_agent.msi ";
        std::wstring configure = command + L"configure";
        for (const wchar_t* name : {L"SERVER_URL", L"CA_FILE", L"CA_FINGERPRINT", L"TOKEN_FILE", L"SERVICE_ACCOUNT"})
            configure += L" " + hex(property(session, name));
        for (const auto& item : {std::make_pair(L"ConfigureAgent", configure),
                std::make_pair(L"RestoreAgent", command + L"restore " + hex(property(session, L"RESTORE_STATE"))),
                std::make_pair(L"PreserveAgent", command + L"preserve"),
                std::make_pair(L"RemoveAgent", command + L"remove"),
                std::make_pair(L"RollbackAgent", command + L"rollback"),
                std::make_pair(L"CommitAgent", command + L"commit")}) {
            if (MsiSetPropertyW(session, item.first, item.second.c_str()) != ERROR_SUCCESS)
                throw std::runtime_error("action");
        }
        return ERROR_SUCCESS;
    } catch (...) {
        return error(session, L"Invalid installer properties. Use HTTPS, a public CA file or SHA-256 fingerprint, and a protected token FILE PATH.");
    }
}

extern "C" __declspec(dllexport) UINT __stdcall RunAgent(MSIHANDLE session) {
    try {
        auto command = property(session, L"CustomActionData");
        // Bound the native wait; no filesystem privilege probe or network here.
        HANDLE sink = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (sink == INVALID_HANDLE_VALUE) throw std::runtime_error("output");
        SetHandleInformation(sink, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        startup.dwFlags = STARTF_USESTDHANDLES;
        startup.hStdInput = sink; startup.hStdOutput = sink; startup.hStdError = sink;
        PROCESS_INFORMATION process{};
        BOOL started = CreateProcessW(nullptr, command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
            nullptr, nullptr, &startup, &process);
        CloseHandle(sink);
        if (!started) return error(session, L"The embedded Python could not start. Repair the MSI and check endpoint protection; system Python is not used.");
        CloseHandle(process.hThread);
        DWORD wait = WaitForSingleObject(process.hProcess, 120000);
        DWORD result = 1;
        if (wait == WAIT_OBJECT_0) GetExitCodeProcess(process.hProcess, &result);
        else { TerminateProcess(process.hProcess, 1); WaitForSingleObject(process.hProcess, 5000); }
        CloseHandle(process.hProcess);
        if (wait != WAIT_OBJECT_0) return error(session, L"Local provisioning timed out. Check administrator rights and file permissions; no source-rights probe was run.");
        if (result == 2) return error(session, L"Invalid configuration. SERVER_URL must be an HTTPS origin without credentials, path or query. CA_FINGERPRINT must be 64 lowercase hexadecimal SHA-256 digits.");
        if (result == 3) return error(session, L"Invalid or missing public CA material. Supply a PEM CA_FILE and, optionally, its matching CA_FINGERPRINT, or a pinned CA fingerprint for service bootstrap.");
        if (result == 4) return error(session, L"Enrollment file rejected. Use a local regular UTF-8 file with one token (at most 8192 bytes), owned and protected for SYSTEM and Administrators only. Do not pass a token as an installer property.");
        if (result == 5) return error(session, L"Unmanaged agent state or a reparse point was found. Resolve the pilot installation or unsafe path before proceeding; identity is not overwritten.");
        if (result != 0) return error(session, L"Local provisioning failed. Check file access and the service account SID. Use an elevated administrator or SYSTEM job; secrets and raw exception details were not logged.");
        return ERROR_SUCCESS;
    } catch (...) {
        return error(session, L"The local provisioning action could not run. Repair the MSI or review the installer properties.");
    }
}
