#include "RegistrationContract.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <algorithm>
#include <limits>
#include <map>
#include <vector>

bool IsValidInstanceName(std::wstring_view value) {
    if (value.empty()) return true; // Optional MSI property.
    const auto alnum=[](wchar_t c){return (c>=L'a'&&c<=L'z')||(c>=L'0'&&c<=L'9');};
    if (value.size()>48||!alnum(value.front())) return false;
    return std::all_of(value.begin(),value.end(),[&](wchar_t c){return alnum(c)||c==L'_'||c==L'-';});
}

namespace {
void Require(bool value) { if (!value) throw RegistrationError(); }
struct Value {
    char kind = 0;
    std::wstring text;
    std::map<std::wstring, Value> fields;
    std::vector<Value> items;
    size_t begin = 0, end = 0;
    Value() = default;
    Value(Value&&) noexcept = default;
    Value(const Value&) = delete;
    ~Value() { if (!text.empty()) SecureZeroMemory(text.data(), text.size() * sizeof(wchar_t)); }
};
class Reader {
    std::string_view input;
    size_t position = 0;
    void White() { while (position < input.size() && (input[position] == ' ' || input[position] == '\r' || input[position] == '\n' || input[position] == '\t')) ++position; }
    char Take() { Require(position < input.size()); return input[position++]; }
    bool Eat(char value) { if (position < input.size() && input[position] == value) { ++position; return true; } return false; }
    unsigned Hex() {
        unsigned value = 0;
        for (int i = 0; i < 4; ++i) {
            const char c = Take();
            Require((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
            value = value * 16 + static_cast<unsigned>(c <= '9' ? c - '0' : c <= 'F' ? c - 'A' + 10 : c - 'a' + 10);
        }
        return value;
    }
    std::wstring String() {
        Require(Take() == '"');
        std::wstring value;
        size_t run = position;
        while (position < input.size()) {
            const auto c = static_cast<unsigned char>(input[position]);
            Require(c >= 0x20);
            if (c == '"' || c == '\\') {
                value += DecodeUtf8(input.substr(run, position - run));
                ++position;
                if (c == '"') return value;
                switch (Take()) {
                case '"': value += L'"'; break;
                case '\\': value += L'\\'; break;
                case '/': value += L'/'; break;
                case 'b': value += L'\b'; break;
                case 'f': value += L'\f'; break;
                case 'n': value += L'\n'; break;
                case 'r': value += L'\r'; break;
                case 't': value += L'\t'; break;
                case 'u': {
                    const auto code = Hex();
                    Require(code < 0xdc00 || code > 0xdfff);
                    value += static_cast<wchar_t>(code);
                    if (code >= 0xd800 && code <= 0xdbff) {
                        Require(Take() == '\\' && Take() == 'u');
                        const auto low = Hex(); Require(low >= 0xdc00 && low <= 0xdfff);
                        value += static_cast<wchar_t>(low);
                    }
                    break;
                }
                default: throw RegistrationError();
                }
                run = position;
            } else ++position;
        }
        throw RegistrationError();
    }
    void Digits() { const auto start = position; while (position < input.size() && input[position] >= '0' && input[position] <= '9') ++position; Require(position != start); }
    Value Read(unsigned depth) {
        White(); Require(position < input.size());
        Value value; value.begin = position;
        const char first = input[position];
        if (first == '{' || first == '[') {
            Require(depth < 8); ++position; White(); value.kind = first;
            const char end = first == '{' ? '}' : ']';
            if (!Eat(end)) {
                while (true) {
                    if (first == '{') {
                        const auto key = String(); White(); Require(Take() == ':');
                        auto child = Read(depth + 1);
                        Require(value.fields.emplace(key, std::move(child)).second);
                    } else value.items.push_back(Read(depth + 1));
                    White(); if (Eat(end)) break;
                    Require(Take() == ','); White();
                }
            }
        } else if (first == '"') { value.kind = 's'; value.text = String(); }
        else if (first == '-' || (first >= '0' && first <= '9')) {
            value.kind = 'n'; Eat('-');
            if (!Eat('0')) Digits();
            if (Eat('.')) Digits();
            if (Eat('e') || Eat('E')) { if (!Eat('+')) Eat('-'); Digits(); }
            value.text = DecodeUtf8(input.substr(value.begin, position - value.begin));
        } else {
            const std::string_view literal = first == 't' ? "true" : first == 'f' ? "false" : "null";
            Require(input.substr(position, literal.size()) == literal);
            position += literal.size(); value.kind = first;
        }
        value.end = position;
        return value;
    }
public:
    explicit Reader(std::string_view bytes) : input(bytes) {}
    Value Parse() { auto value = Read(0); White(); Require(position == input.size()); return value; }
};
void Exactly(const Value& value, std::initializer_list<const wchar_t*> names) {
    Require(value.kind == '{' && value.fields.size() == names.size());
    for (auto name : names) Require(value.fields.contains(name));
}
const std::wstring& Text(const Value& value) { Require(value.kind == 's'); return value.text; }
unsigned Decimal(const std::wstring& text, size_t offset, size_t count) {
    Require(offset + count <= text.size()); unsigned result = 0;
    for (size_t i = offset; i < offset + count; ++i) { Require(text[i] >= L'0' && text[i] <= L'9'); result = result * 10 + static_cast<unsigned>(text[i] - L'0'); }
    return result;
}
std::wstring Origin(std::wstring address) {
    while (!address.empty() && (address.front() == L' ' || address.front() == L'\t' || address.front() == L'\r' || address.front() == L'\n')) address.erase(0, 1);
    while (!address.empty() && (address.back() == L' ' || address.back() == L'\t' || address.back() == L'\r' || address.back() == L'\n')) address.pop_back();
    Require(address.size() >= 9 && address.size() < 4096);
    Require(address.find_first_of(std::wstring{L'@', L'?', L'#', L'\\', L'\0'}) == std::wstring::npos);
    for (auto c : address) Require(c > L' ' && c != 0x7f);
    URL_COMPONENTS parts{}; parts.dwStructSize = sizeof(parts);
    parts.dwHostNameLength = parts.dwUrlPathLength = parts.dwExtraInfoLength = parts.dwUserNameLength = parts.dwPasswordLength = static_cast<DWORD>(-1);
    Require(WinHttpCrackUrl(address.c_str(), static_cast<DWORD>(address.size()), 0, &parts) != 0);
    Require(parts.nScheme == INTERNET_SCHEME_HTTPS && parts.dwHostNameLength > 0 && parts.dwExtraInfoLength == 0
        && parts.dwUserNameLength == 0 && parts.dwPasswordLength == 0);
    const std::wstring path(parts.lpszUrlPath ? parts.lpszUrlPath : L"", parts.dwUrlPathLength);
    Require(path.empty() || path == L"/");
    std::wstring host(parts.lpszHostName, parts.dwHostNameLength);
    // Origin equivalence beyond this native API's normalization is pinned by differential tests.
    for (auto& c : host) if (c >= L'A' && c <= L'Z') c += L'a' - L'A';
    if (host.find(L':') != std::wstring::npos && host.front() != L'[') host = L"[" + host + L"]";
    return L"https://" + host + (parts.nPort == 443 ? L"" : L":" + std::to_wstring(parts.nPort)) + L"/";
}
}

std::wstring DecodeUtf8(std::string_view bytes) {
    if (bytes.empty()) return {};
    Require(bytes.size() <= 16384);
    const auto length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
    Require(length > 0);
    std::wstring value(static_cast<size_t>(length), L'\0');
    Require(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), static_cast<int>(bytes.size()), value.data(), length) == length);
    return value;
}
std::string EncodeUtf8(const std::wstring& text) {
    if (text.empty()) return {};
    const auto length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    Require(length > 0); std::string bytes(static_cast<size_t>(length), '\0');
    Require(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), bytes.data(), length, nullptr, nullptr) == length);
    return bytes;
}
uint64_t ParseUtcTicks(const std::wstring& text) {
    Require(text.size() >= 20 && text.size() <= 35);
    Require(text[4] == L'-' && text[7] == L'-' && (text[10] == L'T' || text[10] == L' ') && text[13] == L':' && text[16] == L':');
    SYSTEMTIME time{};
    time.wYear = static_cast<WORD>(Decimal(text, 0, 4)); time.wMonth = static_cast<WORD>(Decimal(text, 5, 2)); time.wDay = static_cast<WORD>(Decimal(text, 8, 2));
    time.wHour = static_cast<WORD>(Decimal(text, 11, 2)); time.wMinute = static_cast<WORD>(Decimal(text, 14, 2)); time.wSecond = static_cast<WORD>(Decimal(text, 17, 2));
    size_t position = 19; uint64_t fraction = 0;
    if (position < text.size() && text[position] == L'.') {
        ++position; size_t digits = 0;
        while (position < text.size() && text[position] >= L'0' && text[position] <= L'9') {
            if (digits < 7) fraction = fraction * 10 + static_cast<uint64_t>(text[position] - L'0');
            ++digits; ++position;
        }
        Require(digits >= 1 && digits <= 9);
        for (; digits < 7; ++digits) fraction *= 10;
    }
    const auto zone = text.substr(position);
    Require(zone == L"Z" || zone == L"+00" || zone == L"-00" || zone == L"+0000" || zone == L"-0000" || zone == L"+00:00" || zone == L"-00:00");
    Require(time.wYear >= 1601 && time.wYear <= 9999);
    FILETIME file{}; Require(SystemTimeToFileTime(&time, &file) != 0);
    SYSTEMTIME roundtrip{}; Require(FileTimeToSystemTime(&file, &roundtrip) != 0);
    Require(roundtrip.wYear == time.wYear && roundtrip.wMonth == time.wMonth && roundtrip.wDay == time.wDay
        && roundtrip.wHour == time.wHour && roundtrip.wMinute == time.wMinute && roundtrip.wSecond == time.wSecond);
    return (static_cast<uint64_t>(file.dwHighDateTime) << 32) + file.dwLowDateTime + fraction;
}
uint64_t CurrentTicks() { FILETIME file{}; GetSystemTimePreciseAsFileTime(&file); return (static_cast<uint64_t>(file.dwHighDateTime) << 32) + file.dwLowDateTime; }
Registration::~Registration() { if (!enrollment.empty()) SecureZeroMemory(enrollment.data(), enrollment.size()); }
Registration ParseRegistration(std::string_view bytes, uint64_t now) {
    Require(!bytes.empty() && bytes.size() <= 16384);
    Require(!(bytes.size() >= 3 && bytes.substr(0, 3) == "\xef\xbb\xbf"));
    Require(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0) > 0);
    auto root = Reader(bytes).Parse(); Exactly(root, {L"contract_id", L"server_url", L"ca_sha256", L"enrollment"});
    Require(Text(root.fields.at(L"contract_id")) == L"sli.agent-registration.v1");
    Registration result; result.origin = Origin(Text(root.fields.at(L"server_url")));
    result.caPin = Text(root.fields.at(L"ca_sha256")); Require(result.caPin.size() == 64);
    for (auto& c : result.caPin) { Require((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F')); if (c >= L'A' && c <= L'F') c += L'a' - L'A'; }
    const auto& input = root.fields.at(L"enrollment"); Exactly(input, {L"kind", L"token", L"computer_entity_id", L"expires_at"});
    Require(Text(input.fields.at(L"kind")) == L"group");
    const auto& token = Text(input.fields.at(L"token")); Require(token.size() == 43);
    for (auto c : token) Require((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9') || c == L'_' || c == L'-');
    const auto& entity = input.fields.at(L"computer_entity_id"); Require(entity.kind == 'n' && !entity.text.empty());
    uint64_t id = 0;
    for (auto c : entity.text) { Require(c >= L'0' && c <= L'9'); const auto digit = static_cast<unsigned>(c - L'0'); Require(id <= (static_cast<uint64_t>(INT64_MAX) - digit) / 10); id = id * 10 + digit; }
    Require(id != 0); result.entityId = static_cast<int64_t>(id);
    result.expires = ParseUtcTicks(Text(input.fields.at(L"expires_at")));
    Require(result.expires > now && result.expires - now <= 7ull * 86400 * 10000000);
    result.enrollment = std::string(bytes.substr(input.begin, input.end - input.begin));
    Require(DecodeUtf8(result.enrollment).size() <= 8192);
    return result;
}
