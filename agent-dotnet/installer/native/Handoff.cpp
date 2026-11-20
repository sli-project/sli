#include "Handoff.h"
#include "Snapshot.h"
#include <stdexcept>
#include <vector>

namespace {
void Require(bool value) { if (!value) throw std::runtime_error("agent_handoff_invalid"); }
void Field(const std::wstring& value, size_t maximum) { Require(!value.empty() && value.size() <= maximum && value.find_first_of(std::wstring{L'|',L'\0',L'\r',L'\n'}) == std::wstring::npos); }
void Hex(const std::wstring& value, size_t count) { Require(value.size() == count); for (auto c : value) Require((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f')); }
void Check(const StageInput& input) {
    ValidateTransportMetadata(input.snapshotPath,input.snapshotHash,input.origin,input.caPin); Hex(input.transactionId, 32);
}
}
void ValidateTransportMetadata(const std::wstring& path,const std::wstring& hash,const std::wstring& origin,const std::wstring& pin) {
    Field(path,4096);Hex(hash,64);Field(origin,4096);Hex(pin,64);
}
StageInput PrepareStageInput(const std::wstring& path, const std::wstring& hash, const std::wstring& origin, const std::wstring& pin) {
    StageInput input{path,hash,GenerateTransactionId(),origin,pin}; Check(input); return input;
}
std::wstring EncodeStageInput(const StageInput& input) {
    Check(input); return L"sli.registration-reference.v1|" + input.snapshotPath + L"|" + input.snapshotHash + L"|" + input.transactionId + L"|" + input.origin + L"|" + input.caPin;
}
StageInput DecodeStageInput(const std::wstring& value) {
    Require(value.size() <= 10000); std::vector<std::wstring> fields; size_t start=0;
    while (true) { const auto end=value.find(L'|',start); fields.push_back(value.substr(start,end==std::wstring::npos?end:end-start)); if(end==std::wstring::npos)break; start=end+1; }
    Require(fields.size()==6 && fields[0]==L"sli.registration-reference.v1");
    StageInput input{fields[1],fields[2],fields[3],fields[4],fields[5]}; Check(input); return input;
}
void RequireNewBootstrap(bool exists) { Require(!exists); }
