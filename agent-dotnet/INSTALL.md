# T041: сборка и проверка агента .NET

Служба `SLIAgentNet`, программа `%ProgramFiles%\SLI\AgentNet`, состояние
`%ProgramData%\SLI\AgentNet\state`, настройки `HKLM\SOFTWARE\SLI\AgentNet` (64 bit).

## Сборка

SDK закреплён в global.json: 10.0.113. На Windows из корня репозитория:

```powershell
$env:DOTNET_CLI_HOME = "$PWD/.dotnet-home"
$env:NUGET_PACKAGES = "$PWD/.nuget/packages"
$env:PATH = "$PWD/.dotnet;" + $env:PATH
./agent-dotnet/tools/Build-Msi.ps1
./agent-dotnet/tools/Test-MsiTables.ps1 -Msi artifacts/agent-dotnet/SliAgent.msi -PublishDirectory artifacts/agent-dotnet/publish
Get-FileHash artifacts/agent-dotnet/SliAgent.msi -Algorithm SHA256
```

WiX 5.0.2 закреплён в локальном tool manifest; системная установка WiX не требуется.
Выход — self-contained win-x64, без trimming и single-file. `-Version 0.3.6` создаёт
следующую версию для проверки обновления. `-NoRestore` использует ранее восстановленные
инструмент и runtime packs. MSI и вспомогательные файлы остаются в artifacts и не коммитятся.

## Установка на разрешённой ВМ (Сигнал)

Для установки с сервером SLI используйте [команду из раздела «Агенты»](../README.ru.md#агент-windows).
Для ручной проверки MSI на изолированной ВМ с подготовленным токеном регистрации:

```powershell
msiexec /i SliAgent.msi /qn /norestart SERVER_URL=https://sli.example.test ENROLL_TOKEN=<токен>
```

Вместо ENROLL_TOKEN можно задать `TOKEN_FILE=C:\Bootstrap\enrollment.token`.
ENROLL_TOKEN скрыт в свойствах MSI. На первом старте служба переносит значение из
закрытого ключа реестра в DPAPI LocalMachine под защищённым DACL; после успешной записи
удаляет значение из реестра. После регистрации удаляет bootstrap. Секреты не печатаются
службой. Значение ENROLL_TOKEN в команде может быть видно средствам регистрации запуска
процессов; защищённый TOKEN_FILE позволяет не передавать его значением аргумента.

Два параметра достаточны, если сертификат сервера уже доверен Windows. Для частного CA
нужен `CA_FILE=C:\Bootstrap\server-ca.pem` либо `CA_FINGERPRINT=<SHA-256 CA, 64 hex>`.
При fingerprint проверяются и имя сервера, и цепочка до указанного CA. Непроверенный CA
не принимается. Самоподписанный сервер без заранее заданного доверия не может безопасно
регистрироваться только по адресу и секрету.

Существующий сервер связывает одноразовый токен с **уже подготовленными** host_id и ключом.
Для этого пути перед выпуском токена выполнить на целевой ВМ `SliAgent.exe prepare`:
команда печатает только публичные host_id/key_fingerprint. Не копировать ключ с другого ПК.
Для группового пути TOKEN_FILE содержит существующий серверный документ:

```json
{"kind":"group","token":"<43 символа>","computer_entity_id":7,"expires_at":"<UTC>"}
```

Тот же документ можно передать в ENROLL_TOKEN как UTF-8 JSON, кодированный base64url
без padding. computer_entity_id берётся из разрешённого сервером scope. Агент повторяет
pending с тем же ключом; только серверное approved разрешает final enrollment.
Обычная строка группового токена без computer_entity_id не заменяет этот документ.
Сборка комплекта Debian берёт `SliAgent-<SHA>.msi` и `SliAgent-<SHA>.msi.json`
из доверенного кэша. Команда из консоли проверяет закреплённый CA и SHA-256 пакета,
а для подписанного MSI также проверяет Authenticode. Сервер привязывает регистрацию
к ключу из первого принятого CSR.

## Удаление

Обычное удаление MSI очищает настройки и личности агента. Очереди остаются в
`%ProgramData%\SLI\AgentNet\retained-queue-*`. Для удаления вместе с очередями
запустите `msiexec /x SliAgent.msi PURGE_QUEUE=1`.

## Поведение и сохранность

Каждый цикл требует успешный mTLS check-in. Неверная политика останавливает и сбор, и
доставку; старое локальное разрешение не используется. active собирает по серверному
интервалу, paused сохраняет очередь без доставки, drain отправляет накопленное и лишь
после последней точной квитанции сообщает paused. Курсоры и лимиты событий сохраняются
в подписанных пакетах; продвижение — после долговечной записи, удаление — после ACK.

Поддерживаются `sli.windows.ad-dc` и `sli.workstations`, каналы, семейства, фильтры,
серверный batch/rate/spool/interval, проба чтения, policy-report и windows-audit-report.
Включённый неизвестный модуль отклоняется. Нативный аудит использует фиксированные GUID,
проверку SYSTEM и GPO, сохранение намерения до изменения, readback, восстановление при
отказе от управления и блокировку при внешнем дрейфе. Shell/PowerShell не запускаются.
Defender protection_state пока честно unavailable; события Defender собираются.

```powershell
msiexec /i C:\Bootstrap\update\SliAgent.msi /qn /norestart
msiexec /x <ProductCode> /qn /norestart
```

MajorUpgrade сохраняет регистрационный ключ, сертификат, настройки и очередь. Повторно
токен при обновлении не нужен; понижение версии запрещено. Удаление останавливает и
удаляет службу и файлы программы. Состояние и настройки сохраняются для восстановления;
удаление не отзывает серверную запись. Удалённая команда удаления не исполняется этим
этапом. ZIP-обновление сервера отклоняется с agent_update_msi_required.

## Проверка MSI на изолированной Windows-ВМ

`Test-MsiTables.ps1` без установки проверяет одну службу, ожидание её остановки перед
удалением файлов, транзакционное обновление, запрет понижения, сохранение состояния и
параметры команд из README/этой инструкции. Условия регистрационных действий вычисляются
Windows Installer для новой установки, обновления, восстановления и удаления.

Для исполнения полного цикла нужны права администратора и чистая одноразовая ВМ.
Тест отказывается работать при существующих службе, настройках или каталоге агента.
Из корня репозитория в PowerShell 7:

```powershell
./agent-dotnet/tools/Build-Msi.ps1 -OutputRoot artifacts/msi-baseline -Version 0.2.2
./agent-dotnet/tools/Build-Msi.ps1 -OutputRoot artifacts/msi-upgrade -Version 0.2.3 -NoRestore
./agent-dotnet/tools/Test-MsiTables.ps1 -Msi artifacts/msi-baseline/SliAgent.msi -PublishDirectory artifacts/msi-baseline/publish
./agent-dotnet/tools/Test-MsiTables.ps1 -Msi artifacts/msi-upgrade/SliAgent.msi -PublishDirectory artifacts/msi-upgrade/publish -ExpectedVersion 0.2.3
$env:SLI_AGENT_MSI_DISPOSABLE = '1'
$env:SLI_AGENT_MSI_BASELINE = (Resolve-Path artifacts/msi-baseline/SliAgent.msi).Path
$env:SLI_AGENT_MSI_UPGRADE = (Resolve-Path artifacts/msi-upgrade/SliAgent.msi).Path
dotnet test agent-dotnet/tests/Sli.Agent.Tests/Sli.Agent.Tests.csproj --filter FullyQualifiedName~MsiLifecycleWindowsTests
```

Тест устанавливает MSI тихо, обновляет поверх работающей службы без токена, удаляет
при работающей службе и повторно устанавливает без регистрации. Проверяет сохранение
DPAPI-ключа, выданного тестовым CA сертификата, host_id, agent_id, пакета и курсора.
Связь ограничена loopback; реальный сервер и AD не используются. После проверки удаляет
только созданное им состояние. Журналы MSI остаются в каталоге `sli-msi-lifecycle-*`
в TEMP; коды 1603 и требование перезагрузки на чистой ВМ проваливают тест.

Workflow `agent-msi.yml` выполняет обе проверки на Windows. Если нет повышенных прав,
он явно сообщает, что выполнена только проверка таблиц и условий, без установки.

## WindowsOnly и приёмка Сигнала

Локальные тесты не регистрируют службу в SCM. AgentWorkerTests проверяет start/stop с
отменой без SCM. WindowsOnly включает DPAPI, DACL, очередь NTFS, чтение Application с
продолжением по bookmark, безопасную ошибку отсутствующего канала. Два повышенных теста
проверяют синтетический журнал (создание, чтение, потеря якоря после очистки) и Security.

На изолированной Win10 VM выполнить `dotnet test SliAgent.slnx -c Release` и
`tools/Test-WindowsAcceptance.ps1` из agent-dotnet. Повышенный прогон WindowsOnly должен
завершиться без skips. Отдельно проверить MutualTlsTests через SChannel с доступным
тестовым контейнером ключа. В ограниченной локальной сессии T041 PFX-import для тестового
TLS-сервера недоступен; успешный Windows mTLS пока не заявлен.

- [ ] Установить MSI одной тихой командой на чистой Win10 VM без установленной .NET.
- [ ] При частном CA проверить корректный pin и отказ с чужим CA/именем сервера.
- [ ] Агент появляется в «Агентах» с именем компьютера; ключ привязан к правильному scope.
- [ ] Назначить sli.workstations; события станции поступают в SLI.
- [ ] Проверить каналы/семейства, интервал, active → paused → drain → active.
- [ ] Проверить управление аудитом, GPO-блокировку и сохранённый исходный снимок.
- [ ] Отключить сеть, накопить очередь, перезапустить; восстановить сеть и получить ACK.
- [ ] Обновить MSI поверх без токена; host_id, agent_id, ключ и очередь сохраняются.
- [ ] Проверить автозапуск, остановку и восстановление службы без окон. WiX предупреждает
  о native ServiceConfig (WIX1149); отложенный старт и recovery требуют отдельного readback.
- [ ] Удалить MSI: службы и программы нет, состояние сохранено.

Это список последующей приёмки, а не результаты установки. Автор T041 MSI и службу на
ПК владельца не устанавливает и регистрацию против стенда не выполняет.
