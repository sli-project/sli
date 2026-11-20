#include "RegistrationContract.h"
#include <windows.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>

static int checks = 0;
static void Check(bool value, const char* code) { if (!value) throw std::runtime_error(code); ++checks; }
static std::string Body(const std::string& expiry = "2026-10-25T13:00:00Z") {
    return "{\"contract_id\":\"sli.agent-registration.v1\",\"server_url\":\"https://SLI.example.test:8443\",\"ca_sha256\":\""
        + std::string(64, 'A') + "\",\"enrollment\":{\"kind\":\"group\",\"token\":\"" + std::string(43, 'g')
        + "\",\"computer_entity_id\":7,\"expires_at\":\"" + expiry + "\"}}";
}
static std::string Replace(std::string text, const std::string& before, const std::string& after) {
    const auto position = text.find(before);
    if (position == std::string::npos) throw std::runtime_error("test_replacement_missing");
    text.replace(position, before.size(), after); return text;
}
static void Reject(const std::string& input, uint64_t now) {
    try { const auto parsed = ParseRegistration(input, now); (void)parsed; }
    catch (const RegistrationError& error) { Check(std::string(error.what()) == "agent_registration_invalid", "fixed_error"); return; }
    throw std::runtime_error("invalid_input_accepted");
}
int wmain(int argc, wchar_t** argv) {
    for (const auto& value : {L"", L"a", L"0", L"dc_1-test", L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
        if (!IsValidInstanceName(value)) return 1;
    for (const auto& value : {L"DC", L"_dc", L"-dc", L"dc ", L"dc\n", L"a/b", L"a\\b", L"é", L"а", L"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
        if (IsValidInstanceName(value)) return 1;
    try {
        const auto now = ParseUtcTicks(L"2026-10-25T12:00:00Z");
        if (argc == 3 && std::wstring(argv[1]) == L"--parse") {
            std::ifstream file(argv[2], std::ios::binary);
            std::string bytes((std::istreambuf_iterator<char>(file)), {});
            try {
                const auto parsed = ParseRegistration(bytes, now);
                std::cout << "accept\n" << EncodeUtf8(parsed.origin) << '\n' << EncodeUtf8(parsed.caPin) << '\n' << parsed.entityId << '\n';
            } catch (const RegistrationError&) { std::cout << "reject\n"; }
            return 0;
        }
        const auto valid = Body();
        const auto parsed = ParseRegistration(valid, now);
        Check(parsed.origin == L"https://sli.example.test:8443/", "normalized_origin");
        Check(parsed.caPin == std::wstring(64, L'a'), "normalized_pin");
        Check(parsed.entityId == 7, "entity");
        Check(parsed.enrollment == valid.substr(valid.find("{\"kind\""), valid.size() - valid.find("{\"kind\"") - 1), "exact_raw_enrollment");
        Check(ParseRegistration(Replace(valid, ":7,", ":9223372036854775807,"), now).entityId == INT64_MAX, "max_id");
        Check(ParseRegistration(Replace(valid, "SLI.example.test:8443", "sli.example.test:443"), now).origin == L"https://sli.example.test/", "default_port");
        Check(ParseRegistration(Body("2026-11-01T12:00:00+00:00"), now).entityId == 7, "seven_day_boundary");
        Check(ParseRegistration(Body("2026-10-25T12:00:00.0000001Z"), now).entityId == 7, "subsecond_expiry");
        Check(ParseRegistration(Replace(valid, "SLI.example.test", "bücher.example.test"), now).origin == L"https://bücher.example.test:8443/", "unicode_host");
        Check(ParseRegistration(valid + std::string(16384 - valid.size(), ' '), now).entityId == 7, "maximum_document_size");
        for (const auto& input : std::vector<std::string>{
            "", "{}", "[]", "{broken", std::string(16385, 'x'), std::string("\xff\xfe", 2),
            std::string("\xef\xbb\xbf") + valid,
            Replace(valid, "sli.agent-registration.v1", "sli.agent-registration.v2"),
            Replace(valid, "https://", "http://"), Replace(valid, "SLI.example.test:8443", "u:p@SLI.example.test:8443"),
            Replace(valid, "SLI.example.test:8443", "SLI.example.test:8443/path"),
            Replace(valid, "SLI.example.test:8443", "SLI.example.test:8443/?secret=x"),
            Replace(valid, "SLI.example.test:8443", "SLI.example.test:8443/#x"),
            Replace(valid, std::string(64, 'A'), "bad"), Replace(valid, "\"group\"", "\"single\""),
            Replace(valid, std::string(43, 'g'), std::string(42, 'g')),
            Replace(valid, ":7,", ":0,"), Replace(valid, ":7,", ":-1,"), Replace(valid, ":7,", ":1.0,"),
            Replace(valid, ":7,", ":1e0,"), Replace(valid, ":7,", ":true,"), Replace(valid, ":7,", ":\"7\","),
            Replace(valid, ":7,", ":9223372036854775808,"),
            Replace(valid, "\"kind\":\"group\"", "\"kind\":\"group\",\"kind\":\"group\""),
            Replace(valid, "\"kind\":\"group\"", "\"kind\":\"group\",\"\\u006bind\":\"group\""),
            Replace(valid, "\"kind\":\"group\"", "\"kind\":\"group\",\"auto_approve\":true"),
            Replace(valid, "\"contract_id\"", "\"unknown\""),
            Replace(valid, "}}", "},\"auto_trust\":true}"), Replace(valid, "}}", "},}"),
            Replace(valid, "{\"contract_id\"", "{/*comment*/\"contract_id\""),
            Replace(valid, "\"kind\":\"group\"", "\"kind\":\"\\ud800\""),
            Body("2026-10-25T12:00:00Z"), Body("2026-11-01T12:00:00.0000001Z"),
            Body("2026-10-25T13:00:00+01:00"), Body("2026-02-30T12:00:00Z")
        }) Reject(input, now);
        Reject(valid, ParseUtcTicks(L"2026-10-25T14:00:00Z"));
        std::cout << "PASS " << checks << " strict registration checks\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL " << error.what() << '\n'; return 1; }
}
