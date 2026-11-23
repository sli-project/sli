# Установка Windows-агента

[English version](AGENT_INSTALL.en.md) · [Установка сервера](SERVER_INSTALL.ru.md)

В этом документе описаны прежний агент Python и оценочный сценарий Docker. Для агента .NET из нативной беты Debian используйте [руководство по подключению агента Windows](../ru/agents.md).

Python-агент под Apache-2.0 выполняет исходящие HTTPS-соединения с наблюдаемых
Windows-хостов, включая контроллеры домена и рабочие станции. У него нет паролей
БД или доступа к Docker. Начните только с heartbeat; сбор требует отдельного
разрешения. Подробности приведены в [руководстве по регистрации](../agent-enrollment.md).

## Демо-стенд: агент на DC Windows Server 2019

[Оркестратор](../../tools/lab/lab-orchestrate.ps1) выполняется в повышенной
Windows PowerShell 5.1 на ПК владельца с OpenSSH и Docker CLI. Нужны отдельная
чистая VDS Windows Server 2019 (build 17763), готовый SSH-доступ администратором
по ключу `~/.ssh/id_ed25519_demo`, доверенный MSI/build SHA-256 sidecar и публичный
CA текущего SLI. Первое SSH-подключение использует `accept-new`, последующие
проверяют сохранённый ключ хоста. Входные переменные содержат target и пути,
без паролей или токенов:

```powershell
$vds = $env:SLI_LAB_SSH_TARGET
$msi = $env:SLI_LAB_MSI_PATH
$ca = $env:SLI_LAB_CA_PATH
$sha = (Get-Content -LiteralPath ($msi + '.sha256') -Raw).Trim().Split(' ')[0]
.\tools\lab\lab-orchestrate.ps1 -Target $vds -MsiPath $msi -CaFile $ca -MsiSha256 $sha
```

Скрипты создают `LAB-DC01`, лес `demo.example` / `DEMO` и DNS, восемь отделов
в OU «Отделы», OU серверов, рабочих станций и сервисных записей, 150 вымышленных
пользователей (три отключены), две сервисные записи с SPN, 40 объектов компьютеров,
группы VPN/отделов и вложенные группы, включая Backup Operators. Восемь GPO имеют
связи и настройки; парольная политика записывается в `GptTmpl.inf` и AD,
расширенный аудит — в `audit.csv` с CSE
([формат Microsoft](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/eda6a094-5d0a-4516-a3ab-7ee2d38b12b6)).
SACL созданных GPC позволяет наблюдать 5136. Объекты компьютеров — инвентарь;
работающие/присоединённые ОС, NPS/VPN-сервер этим сценарием не устанавливаются.

SYSTEM-задача продолжает работу после переименования/повышения DC (до двух
перезагрузок). Оркестратор ждёт готовности до 30 минут, запускает скрытый
переподключающийся SSH-супервизор с `-R 127.0.0.1:8443:localhost:8443`.
Сервер остаётся локальным; ПК должен оставаться включённым. Сертификату SLI
нужен SAN `localhost`; TLS/CA проверяются. PID супервизора печатается отдельно;
для закрытия туннеля остановите его и дочерний `ssh.exe`. Повторный запуск для
того же target не создаёт второй активный туннель.

Последовательность команд оркестратора для описания PR (SSH передаёт команды
через `powershell.exe -EncodedCommand`, scp использует ключ и `BatchMode=yes`):

1. SSH: создать `C:\SLI-Lab` и `bootstrap` с DACL SYSTEM/Administrators **до** scp.
2. SCP: `lab-common.ps1`, `lab-01-domain.ps1`, `lab-02-populate.ps1`,
   `lab-03-simulate.ps1`, `lab-04-agent.ps1`, `lab-data.json` в `C:/SLI-Lab/`.
3. SSH: `& C:\SLI-Lab\lab-01-domain.ps1`; дождаться `domain-ready` после перезагрузок.
4. Локально: `lab-tunnel.ps1 -Target $vds`; SCP MSI и CA в `C:/SLI-Lab/bootstrap/`.
5. SSH: `& C:\SLI-Lab\lab-04-agent.ps1 -Phase Prepare -MsiSha256 $sha`;
   SCP `bootstrap/prepare.json` обратно (публичные UUID/fingerprint).
6. На ПК `Invoke-LabProcess` захватывает без вывода stdout команды
   `docker exec sli-api-1 python -m server.sli.agents.issue_token --host-id <UUID>
   --key-fingerprint <SHA256> --ttl 900 --actor sli-lab-orchestrator`.
   Не запускайте выпуск токена непосредственно с выводом в терминал.
7. `Write-LabSecret` создаёт защищённый локальный файл; SCP передаёт
   `enrollment.token` в защищённый bootstrap VDS; `finally` удаляет копию на ПК.
8. SSH: `& C:\SLI-Lab\lab-04-agent.ps1 -Phase Enroll`: удаление staging-токена,
   запуск службы, ожидание identity и свежего статуса без ошибки доставки.

Повторный запуск переиспользует принадлежащие стенду объекты, членство, GPO,
DSRM/пароли и identity. Пароли существующих пользователей не сбрасываются;
пропавший файл пароля и совпадение имени с чужим объектом дают отказ. Уже
зарегистрированному агенту новый токен не выпускается. Секреты остаются на VDS
в `C:\SLI-Lab` / защищённом каталоге агента. Не включайте транскрипты.
Manifest воспроизводится на машине разработки командой
`python tools/lab/lab_model.py --output tools/lab/lab-data.json`; Python на VDS
не нужен. PowerShell-файлы — UTF-8 с BOM.

`SLI Lab Day` работает каждые пять минут, в рабочие дни 09:00–18:00 по времени
VDS, с редкими ночными входами. LDAP Negotiate на `127.0.0.1:389` генерирует
успехи, ошибки пароля, ежедневный spray по 30 записям, перебор одной записи,
вход отключённой записи, добавление в Domain Admins, изменение GPO и аудита (4719).
Маркеры сценариев/дня и mutex предотвращают повтор завершённых сценариев и
наложение. Членство/GPO сохраняются для последующих снимков. Запустить
сегодняшние незавершённые сценарии сразу:

```powershell
. .\tools\lab\lab-common.ps1
$key = Join-Path $env:USERPROFILE '.ssh\id_ed25519_demo'
Invoke-LabRemote $vds $key '& C:\SLI-Lab\lab-03-simulate.ps1 -RunDaily'
```

`expected\<UTC-дата>.jsonl` содержит UUID попытки, сценарий, интервал UTC,
синтетическую цель, коды событий, IP, GUID/SID изменений и `executed`.
Это журнал действий, а не доказательство событий Windows/SLI. Верификатор
скачивает JSONL и делает только GET к `events.journal`, exact-event API,
`security.problems` с evidence, `ad.infrastructure` и `ad.gpo.v2` (changes).
Он проверяет источник/время/IP/идентичность и не засчитывает событие дважды.
Нужен существующий API-ключ с этими report grants и `evidence.exact` в защищённом
локальном файле; HTTPS CA должен быть доверенным на ПК. Ключи/политики не создаются.

```powershell
.\tools\lab\lab-verify.ps1 -Target $vds -DomainId $demoDomainId -ApiKeyFile $protectedApiKeyFile
# Для скачанного журнала: -ExpectedDirectory $expectedDirectory вместо -Target.
```

Таблица разделяет Event, AD/GPO и Problem: `FOUND`, `MISSING`, `UNAVAILABLE`,
`SCENARIO_FAILED`. Выход `0` — все требуемые соответствия найдены; `2` — пробелы,
недоступность или неисполненный сценарий; `1` — ошибка подготовки. Problem —
находка с точной ссылкой на событие, а не приёмка конкретного правила подбора.
Для изменений AD/GPO нужны базовый и последующие снимки; начальный импорт
не считается изменением. При задержке сбора повторите сверку позже.

**Граница приёмки:** единственное изменение рабочего SLI — `issue_token`.
По текущему контракту новый агент регистрируется с выключенным сбором.
`lab_agent_registered_waiting_for_server_policy` означает регистрацию без сбора;
`lab_agent_registered_collection_active` — свежий активный статус, не сверку
отчётов. Назначение `ad_dc`, `ad_snapshot`, `gpo_snapshot` и политики аудита
требует отдельного разрешённого действия на SLI. Без этого автоматическое
«зарегистрирован и шлёт события» невозможно в указанном scope. Запуск скриптов
не закрывает AG-SNAP/AG-AUDIT; нужна реальная проверка Windows/SLI.

Проверки: `/opt/venv/bin/python -m pytest tests/unit/test_lab_tools.py` и
`/opt/venv/bin/ruff check --config .github/ruff-ci.toml tools/lab/lab_model.py
tests/unit/test_lab_tools.py` в dev-контейнере; native-разбор/фейки:
`powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File
tests/unit/lab_tools_contract.ps1`. БД/AD в тестах не используются. Остановить
генерацию на VDS: `Disable-ScheduledTask -TaskName 'SLI Lab Day'`.
Удаление домена/VDS автоматически не выполняется.

## Установка на хосте с локальным сервером (пилот) одной командой

На Windows-хосте с локальным Docker-сервером SLI из доверенного checkout:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\install-sli-agent-local.ps1
```

Скрипт сам запрашивает одно подтверждение UAC, если сессия не повышена.
Предварительно сервер `sli-api-1` должен быть запущен, содержать модуль
`server.sli.agents.issue_token` и иметь применённые миграции enrollment,
настроенные issuer, HTTPS и публичный CA. Docker CLI должен быть доступен
локальному администратору. URL берётся из `SLI_HEALTH_URL`, публичный CA —
из `SLI_TLS_CA_FILE` внутри API-контейнера; имя URL должно соответствовать
сертификату. Параметр `-ServerUrl https://example.invalid:8443` переопределяет
origin; `-Container` переопределяет имя контейнера.

По умолчанию проверяется MSI
`C:\SLI-Build\artifacts\SLI-Agent-1.0.0-x64.msi` с SHA-256
`afc08f33a706103be5280dc3daa04b4e3f2c841abc9910bba1a7ea62f5591dd1`.
Параметр `-MsiPath` меняет только путь, проверка закреплённого хеша сохраняется.
После проверки MSI скрипт отключает и останавливает пилотное задание
`SLI Agent`, устанавливает MSI под LocalSystem, выполняет `prepare`
установленным Python и выпускает через Docker токен для полученных
host UUID и fingerprint. Аудит `token_create` и токен сохраняются одной
транзакцией; actor — текущий локальный администратор, TTL — 900 секунд.
Право управления локальным Docker-сервером является границей авторизации
этой административной команды; она не доступна агенту через enrollment API.

Токен записывается прямо в `C:\ProgramData\SLI\Agent\enrollment.token`
с DACL без наследования, только SYSTEM и Administrators; значение не
передаётся в аргументах процессов, MSI properties, логах или выводе.
Служба перезапускается, затем до двух минут проверяются локальная identity
и активная серверная регистрация с тем же UUID/fingerprint и действующим
неотозванным сертификатом. Успех: `Агент зарегистрирован: <host_id>`;
код выхода `0`. При сбое выводится этап/причина, код выхода `1`;
оставшийся файл токена удаляется. Пилотное задание остаётся отключённым.
Повтор команды для уже зарегистрированного MSI-агента проверяет запись
без нового токена; чужая конфигурация URL/учётки отклоняется.

Это только локальный пилот. Сбор требует отдельного назначения модулей/
политики владельцем; массовое развёртывание и групповые токены сюда не входят.

## MSI на компьютер (подготовка AG-DEP-4)

MSI устанавливает одну x64-службу `SLIAgent` на Windows 10 / Server 2016 и новее.
Внутри находятся собственный CPython embeddable и зафиксированные зависимости
агента; системный Python и виртуальное окружение не нужны. Программа размещается
в `C:\Program Files\SLI\Agent`, config, ключи и буфер — в
`C:\ProgramData\SLI\Agent`. По умолчанию защищённый ACL разрешает доступ только
SYSTEM и Administrators. Установка не меняет БД и не развёртывает сервер.

Из повышенной административной сессии или задания развёртывания под SYSTEM:

```powershell
msiexec.exe /i "SLI-Agent-1.0.0-x64.msi" /qn /norestart /L*v "agent-install.log" `
  SERVER_URL="https://example.invalid:8443" `
  CA_FILE="C:\ProgramData\SLI-Bootstrap\server-ca.pem"
```

`SERVER_URL` — HTTPS origin без credentials, пути и query. `CA_FILE` — локальный
публичный PEM bundle CA, который копируется в защищённый каталог агента.
Альтернатива — `CA_FINGERPRINT`: SHA-256 DER-сертификата CA, 64 hex-символа в
нижнем регистре. Служба получает именно этот CA из цепочки TLS handshake и
после этого выполняет обычную проверку сертификата и имени сервера до отправки
HTTP-запроса или токена. Endpoint должен передавать закреплённый CA в цепочке;
если root отсутствует, используйте `CA_FILE`. Оба свойства можно указать вместе
для проверки локального bundle. Локальная установка MSI работает offline;
получение CA по fingerprint и enrollment выполняются службой после установки.

Служба запускается автоматически, готовит собственный ключ и непрозрачный UUID
хоста и ждёт enrollment без сбора источников. Существующий однохостовый токен
связан с подготовленным ключом: получите публичные UUID/SPKI командой `prepare`
установленного интерпретатора под учёткой службы, затем запросите токен у
владельца. По защищённому каналу управления доставьте локальный UTF-8 файл с
одним токеном в `C:\ProgramData\SLI\Agent\enrollment.token`. Его DACL должен
быть без наследования, только для SYSTEM и Administrators; владелец файла —
один из этих principals. Такой же защищённый ACL/owner требуется родительскому
bootstrap-каталогу; UNC, reparse points и hard links файла токена отклоняются.
Ключи и токены нельзя включать в golden image.

Если защищённый bootstrap-файл уже подготовлен, installer может перенести его
через свойство, содержащее **только путь**:

```powershell
msiexec.exe /i "SLI-Agent-1.0.0-x64.msi" /qn /norestart `
  SERVER_URL="https://example.invalid:8443" `
  CA_FILE="C:\ProgramData\SLI-Bootstrap\server-ca.pem" `
  TOKEN_FILE="C:\ProgramData\SLI-Bootstrap\enrollment.token"
```

Installer проверяет ACL исходного файла и удаляет его при чтении, затем помещает
материал в защищённый каталог агента. Служба читает его один раз и удаляет
**до** единственной попытки enrollment, в том числе при неверном содержимом или
отказе сервера. Защищённые bootstrap-файлы локально истекают через час; серверный
TTL токена остаётся обязательным. Просроченный файл удаляется и при недоступном
CA bootstrap. После сетевой ошибки требуется новый токен от владельца;
installer не ждёт серверного ответа. Небезопасный ACL отклоняется до чтения:
такой исходный файл оператор должен исправить или удалить сам. Rollback и
uninstall удаляют bootstrap, принадлежащий MSI. Запрещены `TOKEN=`, значения
токена в MSI properties, MST, environment, аргументах процессов и transcript.
`MsiHiddenProperties` не защищает секреты в командной строке при всех режимах
логирования. Сбор по-прежнему требует существующего enrollment и явного
назначения модулей/политики сервером. Установка не меняет audit policy, группы
и разрешения источников.

`SERVICE_ACCOUNT` по умолчанию равен `LocalSystem`. Можно указать локально
подготовленную учётку службы без пароля в installer, например gMSA, которую
администратор заранее разрешил использовать на этой машине. Log on as a
service и машинную авторизацию предоставляют отдельно. Свойство пароля не
поддерживается. Такой явный выбор добавляет только разрешённый SID учётки в
защищённый ACL рядом с SYSTEM и Administrators; создаваемый службой state
сохраняет эти principals. Учётки с паролем настраиваются через защищённое
локальное администрирование Windows. Repair восстанавливает установленную
учётку и сохраняет config, identity и буфер; install properties не выполняют
повторный enrollment и не заменяют их незаметно.

GPO computer startup scripts, SCCM application jobs и Intune Win32 wrappers
могут применять ту же команду `/qn /norestart` в SYSTEM/per-machine контексте.
MSI и публичный CA сначала размещаются локально; bootstrap доставляется
отдельно, токен нельзя встраивать в политику, MST или команду Intune. Native GPO
Software Installation может использовать MST только с публичными URL/CA-path
properties. Для detection/удаления используется MSI ProductCode. Стандартные
результаты: успех `0`, требуется перезагрузка `3010`, ошибка `1603`; причину
смотрите в понятном сообщении SLI Agent в MSI-логе. Этот PR готовит только
установщик и не разрешает массовое развёртывание.

```powershell
msiexec.exe /x "SLI-Agent-1.0.0-x64.msi" /qn /norestart /L*v "agent-remove.log"
```

Uninstall останавливает/удаляет службу и удаляет принадлежащие MSI локальные
ключи, config и весь буфер без связи с сервером. Если очистка отклонена из-за
reparse point, устраните небезопасный путь; неуспешное удаление не доказывает
отсутствие секретов. Сертификат отзывается отдельно в реестре владельца:
серверный отзыв и drain буфера находятся вне этого установщика. Первый результат
поддерживает один default instance и отклоняет существующую пилотную службу
или чужой state. Major upgrade выполняется по процедуре ниже. ZIP updates
#444/#536 не заменяют MSI-owned файлы: аутентифицированный результат
`agent_update_msi_required` учитывается порогом ошибок серверной партии.
Доставка MSI серверными партиями не поддерживается их текущим контрактом signed ZIP.
Для этого результата в партиях сначала обновите сервер с новой миграцией 195.

### Обновление зарегистрированного MSI-агента

В повышенной Windows PowerShell 5.1 разместите новый и прежний **полные** MSI
локально и получите оба SHA-256 из доверенных артефактов сборки. Windows Installer
LocalPackage из кэша не содержит полного embedded payload для отката.

```powershell
./tools/install-sli-agent-local.ps1 -Upgrade -MsiPath $newMsi -MsiSha256 $newHash -PreviousMsiPath $oldMsi -PreviousMsiSha256 $oldHash
```

ProductCode/версия прежнего MSI должны совпадать с установленным пакетом.
Новый ProductCode отличается, UpgradeCode совпадает, версия MSI выше.
Команда не требует Docker, токена, повторной регистрации или доступности сервера.
До удаления старого продукта внутри MSI-транзакции защищённое дерево ProgramData
целиком переносится в соседний каталог. Новый MSI возвращает его до запуска
SLIAgent, сохраняя identity, DPAPI-ключи, сертификаты, конфигурацию, буфер,
receipts, курсоры и записи отката Windows-аудита. Служба наблюдается 30 секунд.
При сбое установки/запуска возвращается прежний MSI с актуальным состоянием;
команда возвращает ошибку с сообщением об откате. Оба пакета и защищённые логи
остаются в `ProgramData/SLI/Agent.upgrade-work-*`. Неудачный откат сохраняет
состояние для восстановления и не объявляется успешным обновлением.
При таймауте MSI состояние и пакеты сохраняются без вмешательства в потенциально
незавершённую MSI-транзакцию; перед восстановлением нужно дождаться её завершения.

PSRemoting использует ту же команду на повышенном endpoint с локальными путями MSI:

```powershell
Invoke-Command -ComputerName $target -FilePath ./tools/install-sli-agent-local.ps1 -ArgumentList @($newMsi, '', 'sli-api-1', $true, $newHash, $oldMsi, $oldHash)
```

Для SSH разместите доверенный скрипт и пакеты на endpoint и используйте повышенную учётную запись:

```powershell
ssh $target "powershell.exe -NoProfile -NonInteractive -File C:/SLI-Bootstrap/install-sli-agent-local.ps1 -Upgrade -MsiPath C:/SLI-Bootstrap/new.msi -MsiSha256 $newHash -PreviousMsiPath C:/SLI-Bootstrap/previous.msi -PreviousMsiSha256 $oldHash"
```

Интерактивный UAC при удалённом запуске недоступен.
Контракты и unit-тесты не подтверждают приёмку установленной Windows-системы.

### Сборка артефакта

Используйте 64-bit PowerShell 5.1 в x64 MSVC developer environment с tools
`14.44.35207` и Windows SDK `10.0.26100.0`, установленными заранее на Windows
build worker. [Lock-файл](../../tools/msi/toolchain.lock.json) задаёт точные
версии, имена и SHA-256 Python, WiX и Windows wheels со ссылками происхождения.
Поместите все шесть файлов в offline input directory. Сборщик проверяет каждый
архив перед распаковкой, явно раскладывает pywin32/native DLLs и проверяет
импорты embedded интерпретатором. Он не запускает pip/postinstall и не скачивает
wheels. Лицензия CPython и лицензионные metadata wheels включены в payload.

```powershell
./tools/build-sli-agent-msi.ps1 -InputDirectory C:\SLI-Build\inputs `
  -OutputDirectory C:\SLI-Build\artifacts
```

Версия берётся из `VERSION` текущего checkout. Календарная `YYYY.minor.patch`
отображается в MSI как `YYYY-2000.minor.patch` (например, `2026.10.1` → `26.10.1`);
embedded агент сообщает полную версию сборки. Остальные версии сохраняют три
поля в пределах MSI (255/255/65535). Явный `-ProductVersion` должен совпадать
с вычисленной версией; независимое переопределение отклоняется.
Опциональный `-DownloadToolchain` скачивает только закреплённые архивы
WiX/Python с проверкой SHA-256. Результат — MSI и `.sha256`; ошибки прекращают
сборку. Артефакт без подписи; секретов подписания в репозитории/сборщике нет.
Linux unit/structure tests не подтверждают Windows acceptance. Перед выпуском
нужны чистая offline Windows без Python, SCM startup/native imports, reboot без
login, enrollment, repair с сохранением учётки, rollback неуспешной установки
и uninstall readback: службы/процесса и каталогов секретов больше нет.
Установленная приёмка здесь не заявляется.

## Ручная альтернатива: подготовка сервера и Windows-хоста

1. Завершите установку сервера и примените актуальную цепочку миграций штатным
   executor. Подготовьте offline root и online issuer по
   [инструкции CA](../agent-enrollment.md#offline-root-and-online-issuer).
   Никогда не монтируйте закрытый root key в сервер.
2. Настройте [agent overlay](../../deploy/linux/docker-compose.agent.yml)
   с защищёнными файлами CA/issuer на хосте по
   [процедуре рабочей станции](../agent-enrollment.md#тестовая-рабочая-станция).
   Монтируйте issuer только в API и перезапустите TLS listener. TLS агента
   должен доходить до SLI без терминации: используйте
   [TLS passthrough](../agent-enrollment.md#reverse-proxy), а не заголовки сертификатов.
3. Установите поддерживаемый Python (3.11+) на Windows и
   [зависимости только агента](../../sli_agent/requirements.txt).
   Разместите доверенные пакеты `sli_agent` и `sli_collect` так, чтобы этот
   интерпретатор импортировал их независимо от текущего каталога пользователя.
4. Выберите LocalSystem или указанную оператором учётную запись сервиса.
   Предоставьте необходимые права чтения локальных журналов, Log on as a service,
   чтение/исполнение Python и пакетов, чтение config/CA и запись в защищённый state.
   Синхронизируйте часы.

## Настройка и регистрация

Поместите конфигурацию в `%ProgramData%\SLI\Agent\agent.json`, а публичную
цепочку HTTPS CA сервера — по указанному в ней пути. Замените адрес-шаблон;
его имя должно соответствовать сертификату сервера.

```json
{
  "server_url": "https://example.invalid:8443",
  "ca_bundle": "C:/ProgramData/SLI/Agent/server-ca.pem",
  "state_dir": "C:/ProgramData/SLI/Agent/state",
  "collection_enabled": false,
  "event_channels": []
}
```

Защитите config/CA от записи непривилегированными пользователями, а state —
защищённым DACL для выбранной учётной записи и SYSTEM. Выполняйте prepare/enroll
от её имени; явно передайте ей права на ограниченные файлы, созданные
администратором. Используйте установленный интерпретатор, заменив пример пути:

```powershell
$agentPython = 'C:/SLI-Agent/venv/Scripts/python.exe'
$agentConfig = Join-Path $env:ProgramData 'SLI/Agent/agent.json'
& $agentPython -m sli_agent --config $agentConfig prepare
& $agentPython -m sli_agent --config $agentConfig enroll
```

Между `prepare` и `enroll` владелец платформы подтверждает напечатанные UUID
хоста и SPKI fingerprint, затем выдаёт краткоживущий одноразовый токен через
[owner API](../agent-enrollment.md#api). Введите токен только в скрытом prompt
`enroll`; не передавайте его через аргументы, environment, config или transcript.
UUID хоста не является hostname и не доказывает идентичность AD.

## Регистрация сервиса и разрешение сбора

В повышенной PowerShell-консоли из доверенного checkout изучите и запустите
[установщик сервиса](../../tools/install-sli-agent.ps1) сначала без `-Install`,
затем с этим параметром:

```powershell
./tools/install-sli-agent.ps1 -PythonExecutable $agentPython -ConfigPath $agentConfig
./tools/install-sli-agent.ps1 -PythonExecutable $agentPython -ConfigPath $agentConfig -Install
```

Регистрация оставляет `SLIAgent` остановленным с ручным запуском. Перед запуском
завершите настройку учётной записи и ACL в Windows Services. Установщик
не запрашивает/не сохраняет пароль сервисной учётной записи и не предполагает gMSA.
Для консольной оценки рабочей станции используйте
[agent-dev-run.ps1](../../tools/agent-dev-run.ps1) и процедуру регистрации
вместо установки сервиса.

Владелец отдельно включает серверный плагин и назначает разрешённый модуль/политику.
Для `sli.workstations` используйте
[процедуру рабочей станции](../agent-enrollment.md#тестовая-рабочая-станция).
Локальный `collection_enabled=false` управляет legacy-модулем Event Log,
но не отключает назначенный сервером модуль рабочих станций. Отдельно проверьте
Windows audit settings и права каналов; установка не меняет audit policy.

## Проверка, остановка и обновление

Проверьте состояние сервиса/консоли, безопасные коды `state/status.json`,
last-seen в реестре владельца и назначенные модули. Receipt `committed` означает
надёжное сохранение inbox, а не завершённую проекцию или готовый отчёт. Используйте
[процедуру readback](../agent-enrollment.md#подтверждение-результата-и-остановка)
для проверки контролируемого события, replay/restart и безопасной остановки.
Остановите сервис в Windows Services (консоль — Ctrl+C); при необходимости
отдельно отключите назначения модулей/проекцию плагина. При ошибках сохраняйте
state, spool и receipts; не удаляйте их ради видимости успешной обработки.

Docker-updater сервера отвергает пакеты агента и не устанавливает/не обновляет
Windows-сервис. Используйте только доверенные совместимые дистрибутивы агента
через проверенный путь установки Windows; сохраняйте identity/state.
Эта инструкция не подтверждает приёмку установленной системы.
