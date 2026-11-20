#include "RegistrationContract.h"
#include "Snapshot.h"
#include "BootstrapStage.h"
#include "Handoff.h"
#include <windows.h>
#include <msi.h>
#include <msiquery.h>
#include <commdlg.h>
#include <array>
#include <vector>
#include <stdexcept>

namespace {
void Require(bool value) { if(!value)throw std::runtime_error("agent_registration_setup_failed"); }
struct Wipe { std::string& value; ~Wipe(){if(!value.empty())SecureZeroMemory(value.data(),value.size());} };
std::wstring Property(MSIHANDLE session,const wchar_t* name) {
    DWORD size=0; wchar_t empty=L'\0'; const auto status=MsiGetPropertyW(session,name,&empty,&size);
    Require((status==ERROR_SUCCESS||status==ERROR_MORE_DATA)&&size<=32760);
    std::wstring result(static_cast<size_t>(size)+1,L'\0'); DWORD capacity=size+1;
    Require(MsiGetPropertyW(session,name,result.data(),&capacity)==ERROR_SUCCESS); result.resize(capacity); return result;
}
bool Present(MSIHANDLE session,const wchar_t* name) {
    DWORD size=0; wchar_t empty=L'\0'; const auto status=MsiGetPropertyW(session,name,&empty,&size);
    Require(status==ERROR_SUCCESS||status==ERROR_MORE_DATA); return size!=0;
}
void Set(MSIHANDLE session,const wchar_t* name,const std::wstring& value) { Require(MsiSetPropertyW(session,name,value.c_str())==ERROR_SUCCESS); }
bool ExistingBootstrap() {
    HKEY key=nullptr; const auto result=RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SOFTWARE\\SLI\\AgentNet",0,KEY_QUERY_VALUE|KEY_WOW64_64KEY,&key);
    if(result==ERROR_FILE_NOT_FOUND)return false; Require(result==ERROR_SUCCESS);
    DWORD size=0,type=0; const auto value=RegQueryValueExW(key,L"ServerUrl",nullptr,&type,nullptr,&size); RegCloseKey(key);
    Require(value==ERROR_SUCCESS||value==ERROR_FILE_NOT_FOUND); return value==ERROR_SUCCESS;
}
InstallConditions Conditions(MSIHANDLE session) {
    InstallConditions c; c.uiLevel=_wtoi(Property(session,L"UILevel").c_str());
    c.installed=Present(session,L"Installed"); c.related=Present(session,L"WIX_UPGRADE_DETECTED");
    c.removing=Present(session,L"REMOVE"); c.repairing=Present(session,L"REINSTALL");
    c.completeArguments=Present(session,L"SERVER_URL")&&(Present(session,L"ENROLL_TOKEN")||Present(session,L"TOKEN_FILE")); return c;
}
UINT Failed(MSIHANDLE session) {
    const bool ru=(GetUserDefaultUILanguage()&0x3ff)==0x19;
    MSIHANDLE record=MsiCreateRecord(1);
    if(record) {
        MsiRecordSetStringW(record,0,ru?L"Не удалось проверить файл регистрации или безопасно подготовить установку. Обратитесь к администратору. (agent_registration_setup_failed)":L"The registration file could not be verified or setup could not be prepared safely. Contact your administrator. (agent_registration_setup_failed)");
        MsiProcessMessage(session,INSTALLMESSAGE_ERROR,record); MsiCloseHandle(record);
    }
    return ERROR_INSTALL_FAILURE;
}
std::wstring CleanupRecord(const UiSnapshot& snapshot) {
    return L"sli.cleanup.v1|"+snapshot.path+L"|"+snapshot.sha256+L"|"+std::to_wstring(snapshot.identity.volume)+L"|"+std::to_wstring(snapshot.identity.high)+L"|"+std::to_wstring(snapshot.identity.low)
        +L"|"+std::to_wstring(snapshot.directoryIdentity.volume)+L"|"+std::to_wstring(snapshot.directoryIdentity.high)+L"|"+std::to_wstring(snapshot.directoryIdentity.low);
}
DWORD Number(const std::wstring& text) { Require(!text.empty()&&text.size()<=10); uint64_t result=0; for(auto c:text){Require(c>=L'0'&&c<=L'9');result=result*10+static_cast<unsigned>(c-L'0');Require(result<=MAXDWORD);} return static_cast<DWORD>(result); }
void CleanupUi(MSIHANDLE session) {
    const auto value=Property(session,L"RegistrationUiCleanup"); if(value.empty())return;
    std::vector<std::wstring> fields;size_t start=0;
    while(true){const auto end=value.find(L'|',start);fields.push_back(value.substr(start,end==std::wstring::npos?end:end-start));if(end==std::wstring::npos)break;start=end+1;}
    Require(fields.size()==9&&fields[0]==L"sli.cleanup.v1");
    UiSnapshot snapshot;snapshot.path=fields[1];snapshot.sha256=fields[2];snapshot.ownerSid=CurrentUserSid();
    const auto slash=snapshot.path.find_last_of(L'\\');Require(slash!=std::wstring::npos&&snapshot.path.substr(slash+1)==L"bundle.snapshot");snapshot.directory=snapshot.path.substr(0,slash);
    const auto name=snapshot.directory.substr(snapshot.directory.find_last_of(L'\\')+1);Require(name.starts_with(L"sli-registration-")&&name.size()==49);
    snapshot.identity={Number(fields[3]),Number(fields[4]),Number(fields[5])};snapshot.directoryIdentity={Number(fields[6]),Number(fields[7]),Number(fields[8])};
    RemoveOwnedUiSnapshot(snapshot);Set(session,L"RegistrationUiCleanup",L"");
}
StageInput Context(MSIHANDLE session) { return DecodeStageInput(Property(session,L"CustomActionData")); }
bool StageExists(const StageInput& input) { return FileExists(ProductionStageBase()+L"\\"+input.transactionId+L"\\receipt.txt"); }
}

extern "C" __declspec(dllexport) UINT __stdcall ChooseRegistrationFile(MSIHANDLE session) {
    try {
        if(!ShouldChoose(Conditions(session))||ExistingBootstrap())return ERROR_SUCCESS;
        const bool ru=(GetUserDefaultUILanguage()&0x3ff)==0x19;std::array<wchar_t,32768> path{};OPENFILENAMEW dialog{};
        dialog.lStructSize=sizeof(dialog);dialog.lpstrFile=path.data();dialog.nMaxFile=static_cast<DWORD>(path.size());
        dialog.lpstrFilter=ru?L"Файлы регистрации (*.json)\0*.json\0\0":L"Registration files (*.json)\0*.json\0\0";
        dialog.lpstrTitle=ru?L"Выберите файл регистрации, выданный администратором":L"Choose the administrator-issued registration file";
        dialog.Flags=OFN_EXPLORER|OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST|OFN_NOCHANGEDIR|OFN_DONTADDTORECENT;
        if(!GetOpenFileNameW(&dialog))return SelectionResult(false,CommDlgExtendedError());
        auto bytes=ReadOriginalAsUiUser(path.data());Wipe wipe{bytes};const auto registration=ParseRegistration(bytes,CurrentTicks());
        std::array<wchar_t,32768> temp{};const auto size=GetTempPathW(static_cast<DWORD>(temp.size()),temp.data());Require(size>0&&size<temp.size());
        auto parent=std::wstring(temp.data(),size);while(parent.size()>3&&parent.back()==L'\\')parent.pop_back();
        const auto snapshot=CreateUiSnapshot(parent,bytes);SecureZeroMemory(bytes.data(),bytes.size());
        Set(session,L"RegistrationUiCleanup",CleanupRecord(snapshot));
        Set(session,L"REGISTRATION_SNAPSHOT",snapshot.path);Set(session,L"REGISTRATION_SHA256",snapshot.sha256);
        Set(session,L"SERVER_URL",registration.origin);Set(session,L"CA_FINGERPRINT",registration.caPin);Set(session,L"CA_FILE",L"");Set(session,L"ENROLL_TOKEN",L"");
        // Satisfies the unchanged UI launch contract; execute preparation replaces this with the fixed private E destination.
        Set(session,L"TOKEN_FILE",snapshot.path);return ERROR_SUCCESS;
    } catch(...){return Failed(session);}
}
extern "C" __declspec(dllexport) UINT __stdcall ValidateRegistrationFile(MSIHANDLE session) {
    try { if(!Present(session,L"REGISTRATION_SNAPSHOT"))return ERROR_SUCCESS;
        ValidateTransportMetadata(Property(session,L"REGISTRATION_SNAPSHOT"),Property(session,L"REGISTRATION_SHA256"),Property(session,L"SERVER_URL"),Property(session,L"CA_FINGERPRINT"));return ERROR_SUCCESS;
    }catch(...){return Failed(session);}
}
extern "C" __declspec(dllexport) UINT __stdcall ValidateInstanceName(MSIHANDLE session) {
    try {
        if(IsValidInstanceName(Property(session,L"INSTANCE_NAME")))return ERROR_SUCCESS;
        const bool ru=(GetUserDefaultUILanguage()&0x3ff)==0x19;
        MSIHANDLE record=MsiCreateRecord(1);
        if(record){
            MsiRecordSetStringW(record,0,ru?
                L"Недопустимое INSTANCE_NAME: укажите от 1 до 48 символов a-z, 0-9, _ или -, начиная с буквы a-z или цифры. (invalid_agent_instance_name)":
                L"Invalid INSTANCE_NAME: use 1 to 48 characters a-z, 0-9, _ or -, starting with a lowercase letter or digit. (invalid_agent_instance_name)");
            MsiProcessMessage(session,INSTALLMESSAGE_ERROR,record);MsiCloseHandle(record);
        }
        return ERROR_INSTALL_FAILURE;
    }catch(...){return Failed(session);}
}
extern "C" __declspec(dllexport) UINT __stdcall PrepareRegistrationData(MSIHANDLE session) {
    try {
        // Transaction ID is generated here, in execute preparation, never read from a public/UI property.
        const auto input=PrepareStageInput(Property(session,L"REGISTRATION_SNAPSHOT"),Property(session,L"REGISTRATION_SHA256"),Property(session,L"SERVER_URL"),Property(session,L"CA_FINGERPRINT"));
        const auto wire=EncodeStageInput(input);Set(session,L"StageRegistration",wire);Set(session,L"RollbackRegistration",wire);Set(session,L"CommitRegistration",wire);
        Set(session,L"CA_FILE",L"");Set(session,L"ENROLL_TOKEN",L"");
        Set(session,L"TOKEN_FILE",ProductionStageBase()+L"\\"+input.transactionId+L"\\enrollment.json");return ERROR_SUCCESS;
    }catch(...){return Failed(session);}
}
extern "C" __declspec(dllexport) UINT __stdcall StageRegistration(MSIHANDLE session) {
    try {
        Require(MsiGetMode(session,MSIRUNMODE_SCHEDULED)&&CurrentUserSid()==L"S-1-5-18");
        const auto input=Context(session);
        // UserSID is read DIRECTLY from this deferred MSI handle. It is absent from action data and snapshot metadata.
        const auto userSid=Property(session,L"UserSID");Require(!userSid.empty());
        auto bytes=ReadVerifiedSnapshot(input.snapshotPath,input.snapshotHash,userSid);Wipe wipe{bytes};
        const auto registration=ParseRegistration(bytes,CurrentTicks());SecureZeroMemory(bytes.data(),bytes.size());
        Require(registration.origin==input.origin&&registration.caPin==input.caPin);
        // Component costing may predate a concurrent bootstrap appearance. Never succeed with an unstaged TOKEN_FILE.
        RequireNewBootstrap(ExistingBootstrap());
        (void)StageProduction(input.transactionId,registration.enrollment);return ERROR_SUCCESS;
    }catch(...){return Failed(session);}
}
extern "C" __declspec(dllexport) UINT __stdcall RollbackRegistration(MSIHANDLE session) {
    try {Require(MsiGetMode(session,MSIRUNMODE_ROLLBACK)&&CurrentUserSid()==L"S-1-5-18");const auto input=Context(session);if(StageExists(input))RollbackProduction(input.transactionId);return ERROR_SUCCESS;}catch(...){return Failed(session);}
}
extern "C" __declspec(dllexport) UINT __stdcall CommitRegistration(MSIHANDLE session) {
    try {Require(MsiGetMode(session,MSIRUNMODE_COMMIT)&&CurrentUserSid()==L"S-1-5-18");const auto input=Context(session);if(StageExists(input))CommitProduction(input.transactionId);return ERROR_SUCCESS;}catch(...){return Failed(session);}
}
extern "C" __declspec(dllexport) UINT __stdcall ClearRegistrationData(MSIHANDLE session) {try{Set(session,L"StageRegistration",L"");Set(session,L"RollbackRegistration",L"");return ERROR_SUCCESS;}catch(...){return Failed(session);}}
extern "C" __declspec(dllexport) UINT __stdcall ClearCommitData(MSIHANDLE session) {try{Set(session,L"CommitRegistration",L"");return ERROR_SUCCESS;}catch(...){return Failed(session);}}
extern "C" __declspec(dllexport) UINT __stdcall CleanupUiSnapshot(MSIHANDLE session) {try{CleanupUi(session);}catch(...){/* Protected orphan is retained on uncertain cleanup; no SYSTEM pathname fallback. */}return ERROR_SUCCESS;}
extern "C" __declspec(dllexport) UINT __stdcall FinishUiRegistration(MSIHANDLE session) {
    try{const bool hadSnapshot=Present(session,L"RegistrationUiCleanup");try{CleanupUi(session);}catch(...){}
    if(hadSnapshot){const bool ru=(GetUserDefaultUILanguage()&0x3ff)==0x19;MessageBoxW(nullptr,ru?L"Установка завершена. Регистрация и подтверждение по-прежнему проверяются на сервере SLI.":L"Installation finished. Registration and approval must still be checked on the SLI server.",L"SLI Agent",MB_OK|MB_ICONINFORMATION);}}catch(...){}return ERROR_SUCCESS;
}
