#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <string_view>

struct FileIdentity { DWORD volume = 0, high = 0, low = 0; bool operator==(const FileIdentity&) const = default; };
struct UiSnapshot { std::wstring path, directory, sha256, ownerSid; FileIdentity identity, directoryIdentity; bool ownerReadOnly = false; };
std::wstring CurrentUserSid();
std::wstring Sha256(std::string_view bytes);
std::wstring GenerateTransactionId();
std::wstring CanonicalLocalPath(const std::wstring& path);
FileIdentity Identity(HANDLE handle);
UiSnapshot CreateUiSnapshot(const std::wstring& parent, std::string_view bytes);
std::string ReadVerifiedSnapshot(const std::wstring& path, const std::wstring& digest, const std::wstring& msiUserSid, unsigned* readCalls = nullptr);
void RemoveOwnedUiSnapshot(const UiSnapshot& snapshot);
bool FileExists(const std::wstring& path);
std::string ReadOriginalAsUiUser(const std::wstring& path);
#ifdef REGISTRATION_TESTS
void SetSnapshotOpenProbe(void (*probe)());
#endif
