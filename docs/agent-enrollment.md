# Internal agent CA and registry (stage 5A)

This server-only foundation does not install an agent or collect data. The planned
SLI agent is Python, Apache-2.0, including on DCs. Its Windows service runs as
LocalSystem or an identity chosen at installation. This API stores no service
passwords and assumes no gMSA. A host identity is an owner-approved UUID, not a
hostname, AD name, or domain. Enrollment proves possession of the approved key;
it does not independently attest the machine or its AD identity.

## Offline root and online issuer

On an isolated offline machine, create the root:

```sh
python -m server.sli.agents.provision root --key-out root.key --cert-out root.pem
```

On the issuing machine, create its key and transfer only the CSR to the offline
machine:

```sh
python -m server.sli.agents.provision issuer-request --key-out issuer.key --csr-out issuer.csr
```

Offline, sign the request and return only the certificate and public root:

```sh
python -m server.sli.agents.provision sign-issuer --root-key root.key --root-cert root.pem --csr issuer.csr --cert-out issuer.pem
```

Outputs are created exclusively; existing files are never overwritten. Private
files are mode 0600 on Linux. Protect the offline root with filesystem permissions
and offline backups; never mount its key in SLI. Restrict the online key to the
server account. Mount Docker secrets and set:

| Environment | Mounted file/value |
| --- | --- |
| `SLI_AGENT_CA_ROOT_CERT_FILE` | Public offline root PEM |
| `SLI_AGENT_CA_ISSUER_CERT_FILE` | Issuing certificate PEM |
| `SLI_AGENT_CA_ISSUER_KEY_FILE` | Unencrypted issuing PKCS#8 key PEM, restricted secret file |
| `SLI_AGENT_CERT_DAYS` | Optional lifetime, 1–90 days; default 30 |
| `SLI_AGENT_MTLS_CA_FILE` | PEM trust bundle with public root and issuer |
| `ADLOG_TLS_CERT_FILE`, `ADLOG_TLS_KEY_FILE` | Existing HTTPS server identity files |

Root lifetime is ten years, issuer lifetime at most one year. Leaf expiry is
bounded by both CAs; issuance fails if less than an hour remains. No key is kept
in PostgreSQL or returned by the API. Use a dedicated agent CA trust bundle,
separate from the server certificate's public HTTPS trust chain. Restart the TLS
listener after trust-file changes. This first version uses one configured issuer;
overlapping issuer rotation is not implemented. Keep the current issuer available
until agents have renewed or been explicitly re-enrolled under a future rotation
procedure.

The existing HTTPS listener requests an optional client certificate so that UI
login and enrollment continue to work. OpenSSL verifies presented certificates;
agent routes additionally verify the issuing chain, validity, clientAuth profile,
agent/host UUID binding, exact registered certificate fingerprint and revocation
state on every request. Revocation takes effect in the API even on an existing
TLS connection. Renewed certificates may coexist until expiry or explicit revoke;
this allows an agent to retry after losing the renewal response.

## API

Admin routes require an authenticated platform owner, including when ambient
authentication is disabled for local development. An admin role alone is not
enough. Browser mutation origin checks still apply. Responses use `no-store`.
All successful admin reads/mutations and certificate issue/renew/revoke operations
write to the append-only `sli_agent_audit` in the same transaction. Actors are
internal IDs; audit payloads contain no raw tokens, CSRs, keys, names or domains.

| Method and path | Request / result |
| --- | --- |
| POST `/api/v1/admin/agent-tokens` | `{host_id, key_fingerprint, ttl_seconds?}` → raw token once, token ID, expiry |
| GET `/api/v1/admin/agent-tokens` | Latest 100 metadata records; no token or hash |
| POST `/api/v1/admin/agent-tokens/revoke` | `{id}` → revoke unused token |
| GET `/api/v1/admin/agents` | Latest 100 agents, up to 100 certificates each, module assignments and last seen |
| POST `/api/v1/admin/agents/revoke` | `{agent_id, serial}` → revoke one certificate |
| POST `/api/v1/admin/agents/disable` | `{agent_id}` → disable agent and revoke all its certificates |
| POST `/api/v1/admin/agents/modules` | `{agent_id, module_id:"sli.workstations", enabled, config?}` → updated module assignments |
| POST `/api/v1/agent/enroll` | HTTPS, no client cert: `{token, csr_pem}` → agent UUID, certificate and CA chain PEM |
| POST `/api/v1/agent/renew` | mTLS: `{csr_pem}` → certificate and chain for the same agent/host |
| GET `/api/v1/agent/identity` | mTLS → agent UUID and assigned modules; updates last seen |
| GET `/api/v1/agent/revocations?after=0` | Public paged revocation feed, up to 500 entries, `next_cursor` |

Token TTL defaults to 900 seconds, allowed range 60–3600. Tokens contain 256 bits
of entropy, are stored only as SHA-256 hashes, and are consumed atomically once.
Invalid CSRs do not consume a token. Independent tokens for an already enrolled
host cannot create another registry identity. Disabled hosts remain registered;
this API does not silently reactivate or re-enroll them.

For initial enrollment, the owner approves the SHA-256 hex fingerprint of the
agent's DER SubjectPublicKeyInfo. CSR subject must contain exactly one CN equal
to the host UUID and no extensions. Accepted keys: RSA 2048–8192 with exponent
65537, or ECDSA P-256/P-384; SHA-256/384/512 signatures. The issued fixed profile
contains CN=agent UUID, agent and host URI SANs, digitalSignature and clientAuth,
and CA=false. Renewal allows a new key after mTLS authentication, bound to the
existing host. Client-supplied agent IDs, names and certificate extensions never
override identity. Module assignments initially remain empty. The owner can
explicitly assign `sli.workstations` with an enabled flag and a validated policy;
other assignments are preserved. Disabled agents cannot be reactivated through
this route. Assignment changes and the SHA-256 of the policy are audited in the
same transaction; raw policy paths are excluded from audit details.

Revocations are an incremental list, not an X.509 CRL. Persist `next_cursor`,
fetch until an empty page, then poll again. Revocation publication is serialized
through commit so that an older certificate revoked later is not skipped.
Duplicate revocation entries are harmless. Authenticate against the registry on
every agent operation; the feed supplements this check. Existing certificate
history and evidence are retained on revoke/disable.

## Reverse proxy

Use TCP/TLS passthrough to the existing SLI HTTPS listener. For example, an nginx
`stream` proxy forwards the agent TLS connection intact to the private SLI port;
the agent sends its certificate to SLI and validates the HTTPS server there.
The backend port must be restricted by firewall. Do not terminate agent TLS at
an HTTP proxy and forward `X-Client-Cert`, `SSL_CLIENT_CERT`, or verification
headers: this implementation deliberately ignores them. TLS termination and
certificate forwarding would need a separate authenticated proxy transport
contract and are not supported by this stage.

Apply additive migration `156_agent_registry` using the project migration
executor after exact predecessor 155 (`core_identity_scope`). It owns all new
tables through `adlog_storage_owner`; internal FKs reference tables of that same owner, with no
legacy FK requiring additional REFERENCES grants. The runtime has no DDL or
DELETE privileges, and can append but cannot update/delete audit records.

## Targeted verification

Run in the Linux dev container with its `/opt/venv/bin/python` (one container at
a time), without a runtime database:

```sh
/opt/venv/bin/python -m ruff check --config .github/ruff-ci.toml server/sli/agents server/api/routes/agents.py server/api/http_server.py tests/unit/test_agent_ca.py tests/unit/test_agent_registry.py tests/unit/test_agent_api.py tests/unit/test_agent_tls.py tests/migrations/test_agent_registry_migration156.py
/opt/venv/bin/python -m pytest -q tests/unit/test_agent_ca.py tests/unit/test_agent_registry.py tests/unit/test_agent_api.py tests/unit/test_agent_tls.py tests/migrations/test_agent_registry_migration156.py tests/ops/test_route_registry.py tests/ops/test_http_server_bind_security.py
```

The migration tests inspect the SQL contract; they do not apply it to PostgreSQL.
The TLS test performs real local socket handshakes with temporary synthetic keys.
Installed enrollment and migration application require separate runtime acceptance.

## Тестовая рабочая станция

Разрешённый стенд: Windows 10 на Docker-хосте, SLI по
`https://localhost:8443`. Ниже — процедура запуска; она сама по себе не является
подтверждением установленного E2E. Агент читает локальные журналы, получает только
HTTPS URL и публичный CA bundle, не получает доступ к PostgreSQL или Docker.

1. Соберите сервер из нужного checkout и примените миграции штатным executor.
   Для этого пути необходима новая `160_agent_workstation_dispatch` после
   `159_workstation_security`: она разрешает изменение `assigned_modules`,
   действие audit `module_assign`, регистрирует выключенный workstation-плагин и
   даёт runtime узкую функцию создания device identity по принятому agent UUID.
   Старые миграции и checksum не меняются. Если stage 8A уже занял номер 160,
   согласуйте номер до применения; две разные миграции с одним номером недопустимы.
2. Подготовьте offline root и online issuer по разделу выше. В
   `C:/SLI/sli.env` задайте **абсолютные пути к файлам хоста**
   `SLI_AGENT_CA_ROOT_CERT_FILE`, `SLI_AGENT_CA_ISSUER_CERT_FILE`,
   `SLI_AGENT_CA_ISSUER_KEY_FILE`, `SLI_AGENT_MTLS_CA_FILE`. Public trust bundle
   агента для HTTPS сервера — отдельный файл: он должен доверять серверному
   сертификату с SAN `localhost`. Root private key хранится offline и никогда
   не монтируется. Ограничьте ACL online issuer key; файлы secrets находятся в
   `C:/SLI/secrets`.
3. Подключите opt-in overlay к проекту `sli` и перезапустите API с новой client
   trust chain (сертификат сервера продолжает использовать существующие secrets):

   ```powershell
   docker compose -p sli --env-file C:/SLI/sli.env -f deploy/linux/docker-compose.yml -f deploy/linux/docker-compose.agent.yml up -d api post-collection
   ```

   Overlay монтирует четыре файла только в `api`. Consumer работает в уже
   существующем `post-collection`, по 16 пакетов за poll; CA keys ему не нужны.
4. Владелец отдельно включает плагин в существующем lifecycle registry. Текущий
   общий endpoint переключения плагинов поддерживает только remote-access;
   для этого первого стенда используйте следующий **разовый SQL** через штатный
   административный доступ к PostgreSQL. Это не команда агента и не runtime
   credentials. При повторном выполнении revision не меняется без необходимости.
   Для остановки проекции используйте тот же блок с `v_enable := false`.

   ```sql
   begin;
   set local role adlog_plugin_lifecycle_owner;
   do $$
   declare
       v_enable boolean := true;
       v_current public.plugin_installations_v1%rowtype;
       v_action text;
       v_hash text;
   begin
       perform pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'));
       select * into strict v_current from public.plugin_installations_v1
           where plugin_id='sli.workstations' for update;
       if v_current.package_lifecycle<>'registered' then
           raise exception 'workstation_plugin_not_installed';
       end if;
       if (v_current.desired_activation='enabled_manual')<>v_enable then
           v_action := case when v_enable then 'enable' else 'disable' end;
           v_hash := encode(sha256(convert_to('sli.workstations:'||v_action||':'||v_current.revision,'UTF8')),'hex');
           update public.plugin_installations_v1 set
               desired_activation=case when v_enable then 'enabled_manual' else 'disabled' end,
               revision=revision+1, immutable_evidence_count=immutable_evidence_count+1,
               updated_at_utc=now() where plugin_id='sli.workstations';
           insert into public.plugin_lifecycle_operations_v1(operation_uid,plugin_id,requested_action,
               expected_revision,committed_revision,plan_sha256,confirmation_sha256,
               actor_kind,actor_key,outcome)
           values(gen_random_uuid(),'sli.workstations',v_action,v_current.revision,v_current.revision+1,
               v_hash,v_hash,'local_operator','workstation-rehearsal','succeeded');
       end if;
   end $$;
   commit;
   ```

   Прочитайте обратно `read_plugin_states_v1()`: `sli.workstations` должен иметь
   `installed=true`, `enabled=true`. Consumer повторно проверяет это состояние
   в транзакции проекции; отключение сохраняет пакеты в inbox. `configured=true`
   означает наличие bundled importer, не подтверждает Windows audit settings.
5. Откройте **повышенную PowerShell-консоль** в checkout, с установленным
   Python 3.11+ и доступом к Security log. Запустите helper с новым, ещё не
   существующим каталогом и публичным HTTPS CA bundle:

   ```powershell
   ./tools/agent-dev-run.ps1 -Directory C:/SLI-Agent-Test -CaBundle C:/SLI-Public/server-ca.pem -ServerUrl https://localhost:8443
   ```

   Скрипт создаёт venv, ставит только `sli_agent/requirements.txt`, защищает ACL
   каталога и state (текущий SID + SYSTEM), пишет config без секретов и запускает
   `prepare`. `collection_enabled=false` относится к legacy single-channel
   EventLog module; workstation-модуль включается серверным назначением.
   Владелец сверяет напечатанные host UUID и fingerprint DER SPKI, создаёт токен
   через POST `/api/v1/admin/agent-tokens`, затем продолжает helper. `enroll`
   читает одноразовый токен скрытым prompt Python; не передавайте его аргументом,
   через environment, transcript или log. `run` выполняется в консоли, без
   установки сервиса и без изменения audit policy. Ctrl+C завершает run.
6. Через owner GET `/api/v1/admin/agents` получите agent UUID. Назначьте модуль
   через POST `/api/v1/admin/agents/modules` с
   `{"agent_id":"<agent UUID>","module_id":"sli.workstations","enabled":true}`
   или CLI из checkout:

   ```powershell
   python -m server.sli.agents.admin --server-url https://localhost:8443 --ca-bundle C:/SLI-Public/server-ca.pem assign-workstations --agent-id '<agent UUID>'
   ```

   CLI запрашивает скрытым prompt **session token владельца** (`adlog_session`),
   использует тот же owner route, проверяет HTTPS CA и не следует redirects.
   Обычная admin API key не является owner session. Дополнительный `--policy`
   принимает локальный JSON с `policy_revision`, `allow_event_ids`,
   `deny_event_ids`, `allow_process_paths`, `deny_process_paths`, `rate_limits`,
   `rate_window_seconds`, `batch_size`, `channel_generations`. `--disable`
   выключает назначение без отзыва сертификатов. Агент получает назначение по
   mTLS `/api/v1/agent/identity`; без него собирается только heartbeat.

### Ожидаемые Windows audit settings

Владелец проверяет эти настройки отдельно в Advanced Audit Policy Configuration;
helper ничего не включает и не меняет. Повышение прав даёт возможность читать
журнал, но не гарантирует, что Windows генерирует нужные события.

| Наблюдение | Настройка / журнал |
| --- | --- |
| Logon 4624 / 4625 | Logon/Logoff → Audit Logon, Success и Failure, журнал Security |
| Process creation 4688 | Detailed Tracking → Audit Process Creation, Success; command line — отдельная opt-in политика Administrative Templates → System → Audit Process Creation → Include command line in process creation events |
| PnP / USB 6416 | Detailed Tracking → Audit PNP Activity, Success; дополнительно Kernel-PnP/Configuration и DriverFrameworks-UserMode/Operational, если доступны |
| Local administrators 4732 / 4733 | Account Management → Audit Security Group Management, Success; принимается локальная группа с SID `S-1-5-32-544` |
| Defender | Доступный Microsoft-Windows-Windows Defender/Operational; модуль читает 5001, 5010, 5012; сторонний AV может не давать этих событий |

Агент также читает System (Service Control Manager 7045), Security
4697–4702, 4719, 4634/4647 и TaskScheduler/Operational. Наличие Security
подкатегории и доступность дополнительных Operational channels проверяются
владельцем. Command line может содержать чувствительные параметры: её включение
и фильтры процессов требуют осознанного выбора владельца. Наблюдение USB/PnP
не доказывает чтение или копирование файлов.

### Подтверждение результата и остановка

Проверяйте только агрегаты и opaque UUID, без вывода XML, имён, SID пользователей
или process command line. В `state/status.json` ожидаются `sli.workstations`
в `enabled_modules` и отсутствие постоянной delivery ошибки. Логи
`post-collection` содержат объект `agent_packets` с `imported`, `scanned` и
`pending_reasons`; причина `dc_importer_unavailable` сохраняет DC evidence до
stage 8A, `agent_module_unknown` сохраняет неизвестные модули. При сбое проекции
`agent_projection_failed` оставляет evidence и повторяет обработку позже.

Через административный SQL прочитайте количество pending/imported rows в
`sli_agent_packet_inbox` и количество наблюдений в
`sli_plugin_workstations.observations` для тестового agent UUID. `committed`
receipt доказывает сохранение inbox, а не успешную проекцию; пустой импорт может
быть успешным, но не доказывает наличие событий. Для реального E2E нужны новый
контролируемый Security event, наблюдение с тем же agent UUID, отсутствие
повторной записи после replay/restart и readback состояния inbox. Доступ к
отчётам по-прежнему определяется platform permissions, а AD association
появляется только после явной привязки identity, без поиска по hostname.

Остановите console run через Ctrl+C. Чтобы прекратить новую workstation capture,
назначьте модуль с `enabled=false`; чтобы прекратить проекцию, отключите plugin
отдельным lifecycle шагом выше. Не удаляйте inbox, receipts или state как способ
подтверждения успешной обработки. Service install и изменение Windows audit
policy не входят в эту процедуру.

Точечные проверки изменений dispatch/enrollment в Linux dev-контейнере,
по одному контейнеру за раз:

```sh
/opt/venv/bin/python -m ruff check --config .github/ruff-ci.toml server/sli/agents server/sli/agent_ingest.py server/sli/sources/collection_packet_import.py server/api/routes/agents.py scripts/runtime/post_collection_worker.py tests/unit/test_agent_dispatch.py tests/unit/test_agent_admin.py tests/unit/test_agent_api.py tests/unit/test_agent_registry.py tests/unit/test_agent_ingest.py tests/unit/test_agent_dev_tools.py tests/migrations/test_agent_workstation_dispatch_migration160.py
/opt/venv/bin/python -m pytest -q -m 'not postgres_integration' tests/unit/test_agent_dispatch.py tests/unit/test_agent_admin.py tests/unit/test_agent_api.py tests/unit/test_agent_registry.py tests/unit/test_agent_ingest.py tests/unit/test_agent_dev_tools.py tests/unit/test_sli_agent_workstations.py tests/unit/test_workstations_plugin.py tests/migrations/test_agent_workstation_dispatch_migration160.py
/opt/venv/bin/python -m pytest -q tests/migrations/test_agent_workstation_dispatch_migration160.py -m postgres_integration
```

Последняя команда использует только guarded disposable test DSN и отдельную
схему с синтетическими данными; все созданные объекты и роль откатываются.
Она проверяет выполнение узкой identity function, но не заменяет применение
полной миграции 160 и readback прав на установленном baseline.
