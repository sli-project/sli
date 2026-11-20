#pragma once
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

struct RegistrationError : std::runtime_error { RegistrationError() : std::runtime_error("agent_registration_invalid") {} };
struct Registration {
    std::wstring origin;
    std::wstring caPin;
    std::string enrollment;
    int64_t entityId = 0;
    uint64_t expires = 0;
    Registration() = default;
    Registration(const Registration&) = delete;
    Registration(Registration&&) noexcept = default;
    ~Registration();
};
uint64_t ParseUtcTicks(const std::wstring& value);
uint64_t CurrentTicks();
Registration ParseRegistration(std::string_view bytes, uint64_t now);
std::wstring DecodeUtf8(std::string_view bytes);
std::string EncodeUtf8(const std::wstring& text);
bool IsValidInstanceName(std::wstring_view value);
