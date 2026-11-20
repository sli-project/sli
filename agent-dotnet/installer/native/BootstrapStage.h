#pragma once
#include <string>
#include <string_view>
struct StageReceipt { std::wstring transactionId, enrollmentPath; };
std::wstring ProductionStageBase();
StageReceipt StageProduction(const std::wstring& transactionId, std::string_view enrollment);
void RollbackProduction(const std::wstring& transactionId);
void CommitProduction(const std::wstring& transactionId);
#ifdef REGISTRATION_TESTS
StageReceipt StageFixture(const std::wstring& base, const std::wstring& transactionId, std::string_view enrollment);
void RollbackFixture(const std::wstring& base, const std::wstring& transactionId);
void CommitFixture(const std::wstring& base, const std::wstring& transactionId);
#endif
