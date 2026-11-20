#pragma once
#include <string>
struct InstallConditions { bool installed=false, related=false, removing=false, repairing=false, completeArguments=false; int uiLevel=0; };
inline bool ShouldChoose(const InstallConditions& c) { return c.uiLevel >= 5 && !c.installed && !c.related && !c.removing && !c.repairing && !c.completeArguments; }
inline unsigned SelectionResult(bool selected, unsigned error) { return selected ? 0u : error == 0 ? 1602u : 1603u; }
struct StageInput { std::wstring snapshotPath, snapshotHash, transactionId, origin, caPin; };
void ValidateTransportMetadata(const std::wstring& path, const std::wstring& hash, const std::wstring& origin, const std::wstring& pin);
StageInput PrepareStageInput(const std::wstring& path, const std::wstring& hash, const std::wstring& origin, const std::wstring& pin);
std::wstring EncodeStageInput(const StageInput& input);
StageInput DecodeStageInput(const std::wstring& value);
void RequireNewBootstrap(bool exists);
