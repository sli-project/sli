# Контракт протокола агента SLI (эталон — Python-агент)

Документ описывает, как сегодня разговаривают агент (`sli_agent/`, `sli_collect/`)
и сервер (`server/`), и что должен повторить агент на .NET, чтобы работать с
сервером без его изменений. Снимок описания контракта: коммит `f6a748f` ветки `main`.
Ссылки на файлы и функции повторно сверены для T023 с `main`
`ba9e841e231d8b743590265565a82e6f14849ac6`; это проверка ссылок, не изменение протокола.
Сокращение `policies` на сервере означает `server/sli/agents/policies.py`,
на агенте — `sli_agent/policies.py`; `group_deployment` —
`server/sli/agents/group_deployment.py`.

Правила документа:

- Источник истины — код. Каждый пункт имеет ссылку `файл` → функция. Если код и
  этот текст расходятся, прав код; текст надо исправить.
- Ничего не придумано. Что в коде не найдено, вынесено в раздел 13 «Открытые вопросы».
- Номера строк не приводятся: они уплывают. Функции ищутся по имени.
- Все значения в примерах синтетические.

Сокращения: «агент» — Python-агент (эталон), «.NET-агент» — новый, «сервер» — `server/`.

## 1. Транспорт

| Что | Как | Где |
|---|---|---|
| Протокол | Только исходящий HTTPS. Схема `https`, без логина, пути, запроса и фрагмента в адресе. | `sli_agent/config.py` → `AgentConfig.__post_init__` |
| Доверие к серверу | CA-пакет из локального файла (`ca_bundle`); ответ регистрации его не меняет. TLS не ниже 1.2. | `sli_agent/transport.py` → `Transport._context` |
| Клиентский сертификат | Выданный сервером; при регистрации не нужен. | там же |
| Редиректы, прокси-заголовки | Не используются. | `sli_agent/transport.py` (модуль) |
| Тело запроса | Канонический JSON (раздел 4.2), `Content-Type: application/json`. | `Transport._request` |
| Таймаут | 30 с на соединение и обмен. | `Transport._request` |
| Ответ | Принимается только `200` и тело не больше 60 КиБ + 1 байт (`MAX_PACKET_BYTES`), JSON-объект. Любой другой статус — `agent_transport_failed`; тело ошибки агент не читает. | `Transport._request`, `sli_agent/envelope.py` → `MAX_PACKET_BYTES` |
| Повтор POST | Агент сам не повторяет POST при неясном исходе: повтор делает следующий цикл. | комментарий в `Transport._request` |
| Keep-alive для пакетов | Агент держит соединение для `POST /api/v1/agent/packets` и закрывает его после 2 с простоя или смены сертификата/CA/адреса. Сервер закрывает после 5 с простоя и 16 запросов. | `Transport._request`, `server/api/http_server.py` → `AGENT_PACKET_KEEPALIVE_SECONDS`, `AGENT_PACKET_KEEPALIVE_REQUESTS` |
| Скачивание пакета обновления | `GET /api/v1/agent/package?sha256=<hex>`, не больше 256 МиБ, сверка SHA-256. | `Transport.download` |

Сервер:

- Слушатель запрашивает клиентский сертификат необязательно (`ssl.CERT_OPTIONAL`) и
  проверяет его по CA агентов: `server/api/http_server.py` (`load_verify_locations`,
  `verify_mode`). Дальше каждый обработчик сам решает, нужен ли сертификат:
  `server/sli/agents/transport.py` → `peer_certificate` (нужен, иначе
  `agent_mtls_required`, 401) и `require_enrollment_tls` (достаточно TLS без сертификата).
- Лимит тела JSON — 64 КиБ (`MAX_JSON_REQUEST_BYTES`); у администраторских
  запросов групповой регистрации — 512 КиБ.
- Ошибка: JSON `{"error": "<код>"}` и HTTP-статус (400/401/404/409/503):
  `server/api/routes/agents.py` → `_execute`, `server/api/routes/agent_packets.py`.
  Исключение: отклонённый пакет — это **HTTP 200** с квитанцией `rejected`
  (раздел 5).
- Все ответы агентских ручек — `Cache-Control: no-store`.

## 2. Идентичность и регистрация

### 2.1. Локальная идентичность агента

`sli_agent/enrollment.py` → `IdentityStore.prepare`:

- `host_id` — случайный UUID, создаётся один раз и хранится в `host.json`.
- Ключ — ECDSA P-256, создаётся один раз, хранится защищённо (раздел 8).
- Отпечаток ключа `key_fingerprint` = SHA-256 от DER-кодировки `SubjectPublicKeyInfo`,
  hex в нижнем регистре (`enrollment.py` → `fingerprint`, `server/sli/agents/ca.py` → `fingerprint`).
- Команда `prepare` печатает только `host_id` и `key_fingerprint`
  (`sli_agent/__main__.py`).

Именованный экземпляр (`instance_name`, `[a-z0-9][a-z0-9_-]{0,47}`) обязан получить
`host_id` от оператора: `AgentConfig.__post_init__`.

### 2.2. Одноразовый токен

Администратор создаёт токен: `POST /api/v1/admin/agent-tokens`
(`server/sli/agents/registry.py` → `create_token`).

Запрос: `host_id` (UUID), `key_fingerprint` (64 hex), необязательно `instance_name`,
`ttl_seconds` (60…3600, по умолчанию 900).

Ответ: `id`, `token`, `host_id`, `expires_at`, `instance_name`. Токен — 43 символа
`[A-Za-z0-9_-]` (`registry.token_hash`). Сервер хранит только SHA-256 токена.
Таким образом токен привязан к `host_id` и ключу конкретного агента.

### 2.3. Регистрация

`POST /api/v1/agent/enroll` — TLS без клиентского сертификата
(`server/api/routes/agents.py`, `require_enrollment_tls`).

Запрос (`IdentityStore.enroll`):

```json
{"token": "<43 символа>", "csr_pem": "<PEM>", "instance_name": "<необязательно>"}
```

Текущий final enrollment также принимает optional `reported_hostname`: имя, сообщённое
агентом для отображения. Python и .NET передают локальное имя без DNS-запроса; это не
влияет на CSR, SAN, ключ, права или привязку компьютера к токену.

CSR (`IdentityStore.csr`, проверка — `server/sli/agents/ca.py` → `parse_csr`):

- subject — только `CN=<host_id>`;
- расширений нет (иначе `agent_csr_extensions_forbidden`);
- ключ: EC P-256/P-384 или RSA 2048…8192 с `e=65537` (`validate_key`); агент использует P-256;
- подпись CSR с хешем SHA-256/384/512, длина PEM не больше 16384.

Проверки сервера (`registry.enroll`): токен существует, не использован, не отозван,
не истёк; `instance_name` в запросе совпадает с токеном; отпечаток ключа CSR
равен отпечатку токена; для этого `host_id` ещё нет агента (иначе
`agent_host_already_enrolled`, 409).

Ответ (`registry._certificate_response`):

```json
{"agent_id": "<UUID>", "serial": "<hex>", "certificate_pem": "<PEM>",
 "ca_chain_pem": "<PEM: промежуточный + корневой>", "expires_at": "<ISO UTC>"}
```

Профиль сертификата (`ca.IssuingCA.issue`):

- subject `CN=<agent_id>`;
- `BasicConstraints ca=false`, `KeyUsage digitalSignature`, `ExtendedKeyUsage clientAuth` (всё критичное);
- `SubjectAlternativeName`: два URI в таком порядке:
  `urn:sli:agent:<agent_id>`, `urn:sli:host:<host_id>`;
- срок — `SLI_AGENT_CERT_DAYS` (по умолчанию 30, допустимо 1…90).

Что агент проверяет перед сохранением (`IdentityStore._accept`): subject, срок
действия, совпадение открытого ключа с собственным, не-CA, EKU ровно `clientAuth`,
SAN ровно такие же два URI, цепочка 1…4 CA, каждый — CA и действителен,
подписи по цепочке, самоподписанный корень, `digitalSignature`.
При любой неудаче — `agent_certificate_invalid`, ничего не сохраняется.

### 2.4. Групповая регистрация

`POST /api/v1/agent/group-enroll` — TLS без сертификата
(`server/sli/agents/group_enrollment.py` → `submit`).

Запрос (`IdentityStore.enroll_group`): `token`, `computer_entity_id` (целое
1…2⁶³−1), `host_id`, `csr_pem`, необязательно `instance_name`. Других полей нет.

Ответы:

- `{"request_id": "...", "status": "pending"}` — ждём одобрения администратора;
  агент повторяет тот же запрос позже (`submit` узнаёт запрос по токену, отпечатку ключа и `instance_name`).
- `{"request_id": "...", "status": "approved", "token": "<одноразовый токен>", "expires_at": "..."}` —
  автоодобрение (`deployment_scope.auto_approve`) или одобрение администратором
  (`group_deployment.release_approval`). Дальше агент выполняет обычную регистрацию
  (2.3) с выданным токеном (`enroll_group`).

Любой отказ — `group_enrollment_rejected` (401).

### 2.5. Продление сертификата

`POST /api/v1/agent/renew` — mTLS (`registry.renew`). Запрос: `{"csr_pem": "<PEM>"}`.
Ответ — как у регистрации. Ключ **тот же**: старые подписанные пакеты в очереди остаются проверяемыми.

Агент продлевает, когда `now + renew_before_seconds ≥ not_after`
(`renew_before_seconds` по умолчанию 3 суток, `IdentityStore.renew_if_due`).
Просроченный сертификат — `agent_certificate_expired`, работа прекращается, очередь сохраняется.
Сервер при продлении обновляет `key_fingerprint` агента.

### 2.6. Аутентификация агента на сервере

`registry.authenticate` (для каждого запроса с mTLS):

1. Сертификат проверяется по промежуточному CA и профилю (`ca.IssuingCA.verify_client`).
2. `CN` — UUID агента; строка агента блокируется (`for update`); статус `active`.
3. SAN — ровно `urn:sli:agent:<id>`, `urn:sli:host:<host_id>`.
4. Серийный номер есть в `sli_agent_certificates`, не отозван, не истёк, отпечаток совпадает.
5. `last_seen` обновляется — это и есть «сердцебиение» при обычной работе.

Режим `removal_only=True` пускает отключённого агента только за командой удаления (раздел 10).

Отзыв: `POST /api/v1/admin/agents/revoke|disable`; лента отзывов —
`GET /api/v1/agent/revocations?after=<N>` без аутентификации (`registry.revocations`).

## 3. Опрос сервера и политика

### 3.1. Check-in

`GET /api/v1/agent/identity` — mTLS (`server/api/routes/agents.py`, `policies.check_in`).
Агент сверяет `agent_id` ответа со своим (`policies.apply_policy`: `agent_module_identity_mismatch`).

Ответ:

```json
{
  "agent_id": "<UUID>",
  "assigned_modules": [ {"module_id": "...", "enabled": true, "config": {}} ],
  "policy_revision": 7,
  "rights_probe_request": null,
  "collection_policy": {"state": "active", "interval_seconds": 60, "batch_size": 32,
                        "rate_limit_per_minute": 120, "spool_max_bytes": 67108864},
  "eventlog_diagnostics_supported": true,
  "file_audit": {},
  "agent_update": null
}
```

- `file_audit` присутствует только если есть запрос; `agent_update` —
  `{"sha256": "...", "version": "x.y.z"}` или `null` (`updates.advertisement`).
- Поля `manage_windows_audit` и `audit_process_command_line` в `collection_policy`
  присутствуют, только если `manage_windows_audit=true`: старые агенты проверяют ключи строго
  (`policies.check_in`).
- Отключённому агенту с командой удаления вместо этого приходит
  `{"agent_id": "...", "agent_removal": {"command_id": "<UUID>", "action": "uninstall"}}`.

Ограничения `collection_policy` (`sli_agent/control.py` → `collection_policy`):

| Поле | Значения | По умолчанию |
|---|---|---|
| `state` | `active`, `paused`, `drain` | `active` |
| `interval_seconds` | 1…86400 | 60 |
| `batch_size` | 1…128 | 32 |
| `rate_limit_per_minute` | 1…10000 | 120 |
| `spool_max_bytes` | 65536…1073741824 | 67108864 |
| `manage_windows_audit`, `audit_process_command_line` | bool | false |

Лишние ключи — ошибка `agent_collection_policy_invalid`.

`policy_revision` — целое 1…2⁵³−1. Сервер повышает его при каждом изменении
назначения или политики (`policies._next_revision`).

### 3.2. Модули

`assigned_modules` — список объектов `{module_id, enabled, config}`; не более 64
(`sli_agent/modules.py` → `configured_modules`). Модуль включается только явным
`enabled: true`. Для этапа 1 важен `sli.windows.ad-dc` (раздел 7). Остальные —
в разделе 12.

Конфигурация модуля приходит **уже нормализованной** сервером
(`server/sli/plugins/ad/agent_policy.py` → `build_ad_policy`, `policies.assign_module`):
сервер сам создаёт `ADDCModule(host_id, settings).config` и дописывает
`policy_revision` строкой. Допустимые ключи конфигурации `sli.windows.ad-dc`
(`sli_agent/ad_dc.py` → `ADDCModule.__init__`):

`source_name`, `connect_address` (обязательные непустые строки ≤128),
`policy_revision` (строка), `batch_size` (1…128, по умолчанию 32),
`channel_generations` (словарь канал→строка), `channels` (словарь канал→bool),
`allow_event_ids` (список или `null`, до 512, только ID из каталога),
`initial_read_hours` (`"all"` или 0…876000, по умолчанию 24).

### 3.3. Отчёт о применении политики

`POST /api/v1/agent/policy-report` — mTLS (`policies.report`; агент —
`sli_agent/policies.py` → `acknowledge_policy`).

Тело (допустимые ключи; других нет):

```json
{"applied_policy_revision": 7, "collection_state": "active",
 "rights_probe": {"request_id": "<UUID>", "status": "allowed"},
 "eventlog_diagnostics": []}
```

- `applied_policy_revision` — целое от 0 до текущей ревизии сервера.
- `collection_state` — `active` или `paused`. Обязателен, если у агента есть
  `collection_policy` (а у сервера он всегда есть); при `drain` агент сначала
  дренирует очередь и только потом сообщает `paused`; если
  `applied_policy_revision` равна ревизии сервера, состояние обязано
  соответствовать желаемому.
- `rights_probe` — только в ответ на `rights_probe_request`; `status`
  — `allowed`, `denied` или `unavailable`; `request_id` обязан совпасть с ожидаемым.
- `eventlog_diagnostics` — список наблюдений
  (`sli_collect/eventlog_diagnostics.py` → `validate_observations`): каналы из
  фиксированного списка, поля `channel`, `observed_at_utc`, `policy_revision`,
  `error` (только классы и коды, **никогда** текст исключения и XML).

Ответ: `{"applied_policy_revision", "rights_probe", "applied_collection_state"}`.

### 3.4. Порядок цикла

`sli_agent/runtime.py` → `run` (один проход):

1. Загрузить идентичность; попытаться продлить сертификат (сбой не мешает работе до истечения).
2. `GET /api/v1/agent/identity`. Команда удаления → раздел 10.
3. Применить политику (`apply_policy`). При ошибке — «закрыться»: ни сбора, ни отправки,
   код `agent_module_config_unavailable`.
4. Если не `drain` — `policy-report` с применённой ревизией и состоянием.
5. Если не `paused` — отправить накопленные пакеты (раздел 5), не больше
   `rate_limit_per_minute − отправленное за последнюю минуту`.
6. При `drain` и пустой очереди — `policy-report` с `paused`.
7. Обновление (раздел 9), затем `windows-audit-report` и `file-audit-report` (вне этапа 1).
8. Если состояние `active` — собрать пакеты модулей не чаще, чем раз в `interval_seconds`;
   при `collection_policy` пакеты `sli.heartbeat` **не создаются**: check-in и есть сердцебиение
   (`runtime.run`, комментарий «Revisioned check-in…»).
9. Записать `status.json` (только коды, без данных) и подождать:
   `min(interval, 60)` с при успехе, `min(60, 2^n + random(0,1))` с при сбоях.

## 4. Пакет

### 4.1. Структура

Тело `POST /api/v1/agent/packets` (`sli_agent/envelope.py` → `make_packet`):

```json
{"envelope": { ... }, "payload": { ... }, "signature": "<base64>"}
```

Ровно эти три ключа (`verify_packet`). Канонический размер пакета не больше 60 КиБ
(`MAX_PACKET_BYTES`), иначе `agent_packet_size_limit`.

### 4.2. Канонический JSON

`sli_agent/envelope.py` → `canonical`:
`json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)`,
в ASCII. Следствия, которые обязан повторить .NET-агент:

- ключи отсортированы по кодовым точкам Unicode (не по UTF-16!);
- без пробелов; все символы вне диапазона `U+0020…U+007E` (то есть и вне ASCII, и управляющие,
  и `0x7F`) записываются как `\uXXXX` строчными hex-цифрами, символы вне BMP — суррогатной парой;
- короткое экранирование: `\"`, `\\`, `\n`, `\r`, `\t`, `\b`, `\f`; символ `/` не экранируется;
- числа: целые без знака плюс; в пакетах чисел с плавающей точкой нет — .NET-агент их отвергает;
- `NaN`/`Infinity` запрещены.

Хеш и подпись используют **только** эту форму.

### 4.3. Конверт

Ровно 20 полей (`envelope.FIELDS`, схема `config/plugin_architecture_v3.json` → `$defs.agent_envelope`):

| Поле | Правило (`validate_envelope`) |
|---|---|
| `contract_id` | `sli.agent-envelope.v1` |
| `packet_id` | UUID в каноническом написании, строка 1…512 |
| `agent_id` | UUID в каноническом написании |
| `source_instance_id` | строка 1…512 |
| `module_id` | `[a-z][a-z0-9_.-]{0,127}` |
| `module_version` | `\d+\.\d+\.\d+` |
| `policy_revision` | строка 1…512 (в проводе — **строка**, например `"7"`) |
| `channel`, `generation` | строки 1…512 |
| `sequence` | целое, `> 0` (в схеме `minimum: 0`, код строже — вопрос 13.1) |
| `cursor_before`, `cursor_after` | `{"strategy": "record_id"|"bookmark"|"file_offset"|"snapshot", "token": "<строка ≤4096>"}` |
| `payload_contract` | как `module_id` |
| `payload_sha256` | 64 hex, SHA-256 от `canonical(payload)` |
| `record_count` | целое ≥0, равно числу `payload.records` |
| `payload_bytes` | длина `canonical(payload)` |
| `observed_at_utc` | ISO-8601 с нулевым смещением (`+00:00` или `Z`) |
| `continuity_state` | `complete`, `not_proven`, `gap`, `filtered` |
| `filtered_count` | целое ≥0 |
| `lost_count` | целое ≥0 или `null` |

Агент пишет время как `datetime.now(utc).isoformat()`: `2026-10-06T12:00:00.123456+00:00`.

### 4.4. Подпись

`make_packet`, `verify_packet`:

- Сообщение: `b"SLI-AGENT-ENVELOPE-V1\0" + canonical(envelope)` (префикс с завершающим нулевым байтом).
- Ключ агента P-256: ECDSA + SHA-256, подпись в DER (ASN.1 SEQUENCE), `base64` стандартный.
  Для RSA — PSS/MGF1-SHA-256/соль по длине хеша; сервер принимает оба,
  агент выпускает только P-256.
- Сервер проверяет подпись **открытым ключом из клиентского сертификата** mTLS-сессии
  (`server/api/routes/agent_packets.py` → `_authenticate`: `ca.verify_client(der).public_key()`).
  Поэтому ключ подписи пакетов и ключ TLS-клиента — один и тот же.
- Порядок проверки (`verify_packet`): структура → размер → конверт → контракт, хеш и размер
  payload, число записей → подпись. Коды: `agent_packet_invalid`, `agent_packet_size_limit`,
  `agent_payload_hash_mismatch`, `agent_signature_invalid`. Все они приходят как
  `HTTP 400 {"error": "<код>"}` (`agent_packets.try_handle_post`).

### 4.5. Полезная нагрузка `sli.collection-packet.v1`

`sli_collect/packets.py` → `make_packet`, `validate_packet`:

```json
{"contract": "sli.collection-packet.v1",
 "header": {"source": "...", "channel": "...", "generation": "..."|null,
            "record_id_range": {"first": 1, "last": 2},
            "cursor": {"after_record_id": 0, "last_record_id": 2},
            "observed_at_utc": "..."},
 "records": [ {"format": "event_xml", "record_id": 1, "payload": { ... }} ],
 "continuity": {"status": "complete"|"not_proven"},
 "context": {}}
```

Ключи верхнего уровня и `header` — ровно эти. `record_id_range` обязан равняться
минимуму и максимуму `record_id` записей (или `null`/`null`). Форматы записи:
`event_xml`, `accounting_line`, `snapshot_json`; `record_id` у не-`event_xml` — `null`.
У `event_xml` в `payload` обязательны `xml` (строка), `computer_name`, `channel`.

Запись `event_xml` (`sli_collect/eventlog.py` → `parse_event_xml`) содержит ровно ключи:
`computer_name`, `connect_address`, `channel`, `provider_name`, `event_id`, `version`,
`level`, `task`, `opcode`, `keywords`, `record_id`, `time_created`, `machine_name`,
`user_id`, `message` (всегда `null`), `properties`, `xml`. Правила извлечения — раздел 7.3.

## 5. Приём и подтверждение

### 5.1. Запрос

`POST /api/v1/agent/packets` — mTLS (`server/api/routes/agent_packets.py` → `try_handle_post`;
логика — `server/sli/agent_ingest.py` → `receive_packet`). Вся обработка идёт в одной
транзакции под блокировкой строки агента; квитанция отдаётся только после коммита.

### 5.2. Порядок проверок сервера

`receive_packet` (код ошибки → статус квитанции). Первый сбой завершает обработку.

1. `verify_packet` (раздел 4.4) — при сбое HTTP 400.
2. `envelope.agent_id` равен агенту из сертификата — `agent_identity_mismatch`.
3. Пакет с тем же `(agent_id, module_id, sequence)` уже принят: тот же хеш конверта →
   вернуть сохранённую квитанцию со статусом `duplicate` (даже после окна давности);
   другой хеш → `agent_sequence_conflict`.
4. `packet_id` уже встречался — `agent_packet_id_conflict`.
5. Давность: `observed_at_utc` позже 300 с в будущем — `agent_replay_window`;
   старше 7 суток — постоянный отказ `agent_packet_expired` (`rejected`).
   Следующий по порядку подписанный просроченный пакет сохраняет только транспортную
   позицию и разрыв; события не принимаются. Неизвестный пропуск последовательности
   не разрешает продвигать позицию. Последний просроченный конверт хранится отдельно
   от квитанций доставки; его точный повтор снова получает `agent_packet_expired`.
6. Проверка модуля (раздел 7 и 7.5).
7. Порядок: `sequence == предыдущий + 1` (или 1) — иначе `agent_sequence_gap`
   со статусом `retry_later`.
8. Тот же поток: `source_instance_id` и `channel` не меняются —
   `agent_stream_identity_changed`.
9. Поколение (`generation`) то же: `cursor_before == предыдущий cursor_after` —
   иначе `agent_cursor_mismatch`. Поколение новое: `cursor_before.token == ""` и
   `continuity_state == "gap"` (для первого пакета `gap` не требуется) — иначе
   `agent_reset_invalid`.
10. Квота входящих (`server/sli/agents/inbox_quota.py` → `quota_error`) —
    `retry_later`.
11. Запись в `sli_agent_receipts` и очередь импорта (`PostgresLedger.commit`).

### 5.3. Квитанция

`agent_ingest._receipt`; схема `$defs.receipt`:

```json
{"contract_id": "sli.agent-receipt.v1", "packet_id": "<UUID>", "payload_sha256": "<hex>",
 "status": "committed", "committed_cursor": {"strategy": "...", "token": "..."},
 "evidence_ref": "agent-packet:<packet_id>", "committed_at_utc": "<ISO UTC>", "error_code": null}
```

Статусы: `committed`, `duplicate`, `rejected`, `retry_later`. Для `rejected` и
`retry_later` поля `committed_cursor`, `evidence_ref`, `committed_at_utc` — `null`, `error_code` — код.
Все они приходят с **HTTP 200**.

### 5.4. Что агент считает подтверждением

`sli_agent/spool.py` → `Spool.acknowledge`. Пакет удаляется из очереди, только если:

- статус `committed` или `duplicate`;
- `packet_id`, `payload_sha256` совпадают с отправленными;
- `committed_cursor == envelope.cursor_after`;
- `evidence_ref` — непустая строка; `committed_at_utc` — корректное время UTC;
  `error_code` равен `null`;
- пакет — **первый в очереди своего модуля** и его `sequence` равен
  `committed + 1`.

Исключение: точный `rejected` с `error_code="agent_packet_expired"`, совпадающими
`contract_id`, `packet_id`, `payload_sha256` и пустыми `committed_cursor`, `evidence_ref`,
`committed_at_utc` окончательно закрывает первый пакет модуля. Агент сначала сохраняет
`committed`, разрыв (`gap_pending`, `expired_from_utc`, `expired_to_utc`), затем удаляет файл.
Это отказ, а не подтверждение доставки. Следующий пакет несёт `continuity_state="gap"`;
уже записанный пакет атомарно переподписывается с тем же идентификатором, содержимым,
курсорами и временем. После подтверждения этого пакета признак ожидания разрыва снимается.

Любое иное — пакет остаётся, модуль блокируется до следующего цикла
(`runtime.deliver_once`). Подтверждение вне порядка курсор не двигает.

## 6. Очередь на агенте

`sli_agent/spool.py` → `Spool`; доставка — `runtime.deliver_once`; съём —
`runtime.capture_module`. Свойства, которые должен сохранить .NET-агент:

- Один пишущий; каталог под блокировкой (`directory_lock`).
- Пакет — файл `<packet_id>.packet` (канонический JSON пакета); атомарная запись с
  `fsync` каталога (`protection.atomic_write`).
- `checkpoints.json`: по каждому модулю `{"committed": <последний подтверждённый sequence>,
  "captured": <конверт последнего снятого пакета>}`. Порядок записи: сначала пакет, потом
  чекпоинт `captured`; при подтверждении — сначала чекпоинт `committed`, потом удаление файла.
- Восстановление после сбоя (`_recover`): пакеты с `sequence ≤ committed` удаляются;
  `captured` пересчитывается по файлам.
- Следующий `sequence` = `captured.sequence + 1`. Новый съём разрешён только если
  `cursor_before` образца равен `captured.cursor_after` того же поколения; смена
  `agent_id`, `source_instance_id` или `channel` — ошибка (`agent_spool_identity_mismatch`,
  `agent_capture_stream_changed`, `agent_capture_cursor_mismatch`).
- Лимит размера **останавливает съём, но не вытесняет данные**: `agent_spool_size_limit`
  (по умолчанию 64 МиБ). Возраст головы очереди не блокирует новый съём.
- Доставка: пакеты идут по модулям в порядке `sequence`; после сбоя одного пакета
  остальные пакеты этого модуля пропускаются в этом цикле; модули не блокируют друг друга.
  У модулей-снимков (`MODULE_FAMILIES`) — не больше `batch_size` пакетов за цикл. Пакеты
  истории DC (`sli.windows.ad-dc-history`) отправляются последними и только если остальные
  отправки в этом цикле успешны.
- Курсор модуля двигается **только** после долговечной записи пакета: следующее чтение
  берёт `captured.cursor_after`, а не память процесса (`capture_module`).

## 7. Журнал Security контроллера домена (`sli.windows.ad-dc`)

Это модуль этапа 1. Источники: `sli_agent/ad_dc.py` (`ADDCModule`, `cursor_state`,
`read_local`), `sli_collect/bookmarked_eventlog.py` (`read_local`), сервер —
`server/sli/plugins/ad/agent_policy.py` (`dc_event_rows`), `server/sli/agent_ingest.py`.

### 7.1. Параметры конверта

| Поле | Значение |
|---|---|
| `module_id` | `sli.windows.ad-dc` (история — `sli.windows.ad-dc-history`, вне этапа 1) |
| `module_version` | `1.0.0` |
| `source_instance_id`, `generation` (конверт) | `host_id` |
| `channel` (конверт) | `ad-dc` |
| `policy_revision` | `config.policy_revision` (строка) |
| `payload_contract` | `sli.collection-packet.v1` |
| `cursor_*.strategy` | `bookmark` |
| `lost_count` | `0`; `null` при сбросе поколения, ошибке чтения или восстановлении закладки |
| `continuity_state` | `gap` при сбросе/ошибке чтения/восстановлении; `filtered`, если были отфильтрованные события; иначе `not_proven` |

Серверная привязка: `identity.assigned_modules` содержит включённое назначение модуля;
ревизия политики пакета есть в назначении или в истории назначений (`agent_ingest._capture_assignment`).

### 7.2. Курсор-закладка

`ad_dc.cursor_state`. `token` — канонический JSON (раздел 4.2), не длиннее 4096 символов:

```json
{"next": 0, "channels": {"Security": {"record_id": 105, "bookmark": "<строка ≤2048>",
                                       "generation": "<строка ≤128>", "since_utc": "..."}}}
```

- `next` — индекс следующего канала по кругу из `("Security", "System", "Directory Service")`.
- На канал: `record_id` (целое >0 или `null`), `bookmark` (непустая строка ≤2048 тогда и
  только тогда, когда `record_id` не `null`), `generation` (непустая ≤128). Допустимы
  дополнительные `since_utc`, `before_utc`, `complete`; других ключей нет.
- Пустой токен (`""`) — начало потока: `{"next": 0, "channels": {}}`.
- Сервер **не разбирает содержимое закладки** — только тип и длину. Формат закладки
  выбирает агент; Python-агент хранит XML закладки Windows
  (`EvtRender(..., EvtRenderBookmark)`).
- Каналы с `channels[канал] == false` в конфигурации пропускаются; серверная проверка
  ротации учитывает только включённые каналы (`dc_event_rows`: `active_channels`).
  Для чтения только Security назначение должно выключить `System` и `Directory Service`.

### 7.3. Чтение и разбор события

Выбор событий (`ad_dc.read_local`, `read_local` в `bookmarked_eventlog.py`):

- Запрос XPath к каналу, прямой порядок. Для Security — объединение условий по ID событий
  из каталога: близкие ID (разрыв ≤16) группируются в диапазон
  `(EventID >= a and EventID <= b)`, одиночные — `EventID=n`. Если закладка уже есть,
  добавляется `EventRecordID=<record_id>`, чтобы якорь оставался доступным.
- Первое чтение канала без закладки: ограничение `TimeCreated[@SystemTime >= since]`,
  где `since = now − initial_read_hours` (если `initial_read_hours != "all"`), и `since_utc`
  записывается в прогресс канала.
- Продолжение: `EvtSeek` относительно закладки со строгим режимом, затем чтение якоря
  (1 событие) и проверка: `EventRecordID` якоря равен сохранённому `record_id`.
  После якоря читается пачка до `batch_size`.
- `ERROR_NO_MORE_ITEMS` (259) — пустая пачка. Закладка (`ERROR_NOT_FOUND`, 1168) пропала
  из журнала при `recover_missing_bookmark=True` — чтение с `EventRecordID > record_id`
  без закладки и пометка «восстановление закладки» (разрыв). Любая другая ошибка Windows —
  `agent_ad_dc_read_failed`, пакет без записей с `read_error`.
- После каждого прочитанного события закладка обновляется (`EvtUpdateBookmark`) и
  сохраняется как XML (`EvtRender`, `EvtRenderBookmark`) вместе с XML события.
- Ошибка чтения не бросает исключение: создаётся пакет с `context.ad_dc.read_error =
  "agent_ad_dc_read_failed"`, без записей, курсор остаётся прежним
  (`ADDCModule.collect`).

Пачка и размер (`ADDCModule.collect`): `len(rows) ≤ batch_size`; `record_id` строго
возрастают и больше предыдущего; канал в XML (`System/Channel`) равен читаемому;
событие входит в каталог по тройке `(канал, provider_name без регистра, event_id)`
и в `allow_event_ids`, если он задан; иначе оно **отфильтровано** (курсор всё равно
сдвигается на него, `filtered_count` растёт). Канонический размер полезной нагрузки
не больше `44 КиБ`; при превышении записи откладываются до следующего пакета
(`catch_up_channel`) — отложенное событие курсором не потребляется. Одно событие больше лимита —
`agent_ad_dc_event_size_limit`.

Разбор `parse_event_xml` — сервер **заново разбирает** `xml` каждой записи и требует
побайтового равенства всего словаря (`dc_event_rows`: `native != row` → отказ). Поэтому
разбор в .NET-агенте обязан давать те же значения:

- пространство имён `http://schemas.microsoft.com/win/2004/08/events/event`;
- `provider_name` — атрибут `Name` первого `System/Provider`;
- `event_id`, `version`, `level`, `task`, `opcode`, `record_id` — целое из текста первого
  элемента; пустой текст или не-число — `null`;
- `keywords`, `machine_name` (`System/Computer`) — текст элемента как есть;
- `time_created` — атрибут `SystemTime` первого `System/TimeCreated` как есть;
- `user_id` — атрибут `UserID` у `System/Security`;
- `properties` — список текстов всех `EventData/Data` по порядку; пустой элемент — `null`;
- `computer_name` — `source_name` из конфигурации; `connect_address` — из конфигурации;
  `channel` — читаемый канал; `message` — всегда `null`; `xml` — строка XML события без изменений.

Ограничения XML (`server/sli/storage/xml_safety.py` → `parse_bounded_xml`): до 4 МиБ,
глубина до 64, до 100000 узлов, DTD и сущности запрещены.

### 7.4. Содержимое пакета

Полезная нагрузка (`ADDCModule.collect`):

- `header.source` = `source_name`; `header.channel` = канал (`Security`);
  `header.generation` = `channel_generations[канал]` или `host_id`;
  `header.cursor` = `{"after_record_id": <было>, "last_record_id": <стало>}`;
  `continuity.status` = `not_proven`;
- `context.ad_dc` = `{"pack_id": "sli.windows.ad-dc", "policy_revision": "<строка>",
  "filtered_count": N, "channel_reset": bool, "read_error": null|"agent_ad_dc_read_failed",
  "channels": {...}, "channel_generations": {...}}` и при восстановлении закладки
  `"bookmark_recovered": true`.

### 7.5. Что проверяет сервер для этого модуля

`dc_event_rows` (вызывается из `receive_packet`). Все нарушения — `agent_collection_cursor_invalid`
(квитанция `rejected`; для не прошедшей привязки — `agent_source_not_bound`, для
неназначенного модуля — `agent_module_not_assigned`):

- оба курсора разбираются `cursor_state`; канал пакета — следующий по кругу среди
  включённых (допускается повтор предыдущего канала при продолжении);
- `header.cursor == {"after_record_id": <record_id канала в cursor_before>, "last_record_id": <record_id в cursor_after>}`;
- остальные каналы в `cursor_after` не изменились; `next == (индекс + 1) % 3`;
- `envelope.channel == "ad-dc"`, `generation == source_instance_id == host_id`;
- `context.ad_dc` согласован с конвертом: `pack_id`, `policy_revision`, `filtered_count`,
  `channel_reset == (поколение сменилось)`, `read_error`;
- `lost_count` — `null` при сбросе/ошибке/восстановлении, иначе `0`;
- `continuity_state` — по правилу из 7.1; `payload.continuity.status == "not_proven"`;
- `record_id` записей возрастают, больше `start`, не больше `last`; при отсутствии
  фильтрации и ошибки `last` равен последнему `record_id`; при ошибке чтения записей и
  фильтрации нет и `last == start`;
- каждое событие — в каталоге (`config/source_packs/dc.json` →
  `config/event_catalog.json`, 41 запись для Security, провайдеры
  `Microsoft-Windows-Security-Auditing` и `Microsoft-Windows-Eventlog`) и разбирается заново
  с равенством словаря (7.3); `connect_address` равен политике;
- границы `since_utc`/`before_utc` соблюдены; для первого чтения `since_utc` равно
  `observed_at_utc − initial_read_hours`;
- `len(rows) + filtered ≤ batch_size`.

## 8. Защита ключей и состояния

`sli_agent/protection.py`:

- Ключ — PKCS#8 PEM в контейнере `{"protection": "dpapi_local_machine"|"restricted_file",
  "data": "<base64>"}`. DPAPI — `CryptProtectData` с флагами `CRYPTPROTECT_LOCAL_MACHINE |
  CRYPTPROTECT_UI_FORBIDDEN` (`0x4 | 0x1`) и описанием `"SLI agent key"`
  (`store_private_key`). Без привязки к DPAPI остаётся файл с жёстким ACL.
- Каталог и файлы состояния получают защищённый DACL: только SID службы и `SYSTEM`
  (плюс «Администраторы» для каталога под управлением MSI с маркером `.msi-owned`)
  (`restrict_path`). Ошибка ACL фатальна. Символьные ссылки отвергаются.
- Запись файлов атомарна: временный файл → `fsync` → `MoveFileEx(REPLACE_EXISTING|WRITE_THROUGH)`.
- Служба проверяет, что процесс запущен от выбранного SID, до любого доступа к состоянию
  (`runtime.run`: `service_identity_verified`).
- Для TLS Python создаёт на время соединения файл с ключом в защищённом каталоге
  (`Transport._context`: требование API OpenSSL), удаляя его до сетевого запроса.
  Как передать ключ клиентского сертификата в TLS-стек .NET без файла, нужно проверить
  на Windows.

## 9. Обновление агента

Сервер (`server/sli/agents/updates.py`):

- Администратор загружает ZIP: `POST /api/v1/admin/agent-packages` (`updates.upload`).
  Пакет проверяется `verify_package` по файлу доверия `SLI_AGENT_UPDATE_TRUST_FILE`;
  манифест: `schema_version == 2`, `component == "agent"`, в `compatibility` есть `agent_api`;
  затем `sli_agent/updates.py` → `validate_payload` требует **набор Python-файлов** (см. 13.3).
- Назначение: `POST /api/v1/admin/agents/update-policy` и волны (`update_waves`).
- Предложение агенту — поле `agent_update` в check-in (`updates.advertisement`).
- Скачивание: `GET /api/v1/agent/package?sha256=<hex>` — только назначенный пакет
  (`updates.download`).
- Результат: `POST /api/v1/agent/update-result` с телом ровно
  `{"sha256", "status", "reason", "version"}`; `status` — `updated`, `rejected`
  или `rolled_back`; `reason` — `null` только при `updated`, иначе из набора
  `REASONS` (`sli_agent/updates.py`); `version` — `x.y.z` (`updates.report`).

Python-агент: `sli_agent/updates.py` → `Updates` (указатель `current.json`,
каталоги `versions/<версия>`, откат, самопроверка `healthy`), `sli_agent/launcher.py`.
Для агента, установленного MSI, ZIP-предложение отклоняется с причиной
`agent_update_msi_required` (`sli_agent/msi.py` → `report_zip_offer`).

## 10. Удаление

- Команда приходит в ответе check-in вместо политики (раздел 3.1); запрашивает администратор
  `POST /api/v1/admin/agents/remove` или сам агент `POST /api/v1/agent/uninstall` с пустым
  телом `{}` (`server/sli/agents/removal.py`).
- Агент проверяет форму команды (`sli_agent/removal.py` → `validate_command`: ровно
  `agent_id` и `agent_removal{command_id, action="uninstall"}`) и запускает удаление фиксированной
  командой `msiexec /x <ProductCode> /qn /norestart` без путей и аргументов от сервера.
- Результат: `POST /api/v1/agent/removal-result` с телом ровно
  `{"command_id", "state", "reason"}`; `state` — `state_cleaned` (с `reason: null`) или
  `cleanup_failed` с причиной из `agent_removal_requires_admin`,
  `agent_removal_unmanaged`, `agent_removal_cleanup_failed` (`removal.report`).

## 11. Локальная настройка и установка (как сейчас)

- Конфигурация — JSON `%ProgramData%\SLI\Agent\agent.json`
  (`sli_agent/config.py` → `machine_config_path`, `AgentConfig`): `server_url`,
  `ca_bundle`, `state_dir`, `collection_enabled`, `event_channels`, `spool_max_bytes`,
  `spool_max_age_seconds`, `renew_before_seconds`, `interval_seconds`, `instance_name`,
  `host_id`, `service_identity_sid`, `allow_missing_rights`, `ca_fingerprint`, поля обновлений.
- MSI-установка Python-агента (`sli_agent/msi.py` → `provision`): создаёт защищённый
  каталог с маркерами `.msi-owned` (`sli-agent-msi-v1`) и `.msi-pending`, `agent.json`,
  `server-ca.pem` (или берёт CA по отпечатку, `ensure_ca`), и, при наличии, файл токена.
- Файл токена: `enrollment.token` — одна строка токена (≤8192 байт, без пробелов), либо
  `enrollment.group` — JSON `{"kind": "group", "token", "computer_entity_id", "expires_at"}`.
  Файл прочитывается и удаляется при первом использовании; одиночный токен старше
  `BOOTSTRAP_TTL = 3600` с считается просроченным, групповой — не дольше `GROUP_TTL = 604800` с
  (`msi.py` → `enroll_once`, `enroll_group_once`, `expired_bootstrap`, `group_bootstrap`).
- Проверка прав чтения журналов — `sli_agent/probe.py` (`sli.agent-rights-probe.v1`),
  вне этапа 1.

## 12. Что не входит в этап 1

Модули и ручки, которые .NET-агент пока **не** реализует; все они обязательны для
полной замены (этап 2 и далее):

`sli.heartbeat` (нужен только для серверов без `collection_policy`), `sli.windows-eventlog`
(общий журнал с курсором `record_id`), `sli.windows.ad-dc-history`, `sli.workstations`,
`sli.file-audit`, `sli.vpn-nps`, `sli.radius-accounting`, модули-снимки
(`sli_agent/snapshot_stream.py` → `MODULE_FAMILIES`: AD и GPO), управление аудитом Windows
(`POST /api/v1/agent/windows-audit-report`, `sli_agent/windows_audit.py`), отчёт файлового
аудита, проба прав, группа обновлений и удаление.

## 13. Открытые вопросы и расхождения

13.1. **`sequence`**: схема `config/plugin_architecture_v3.json` допускает `0`, код
(`validate_envelope`) требует `> 0`. .NET-агент следует коду (первый пакет — `1`).

13.2. **Один `host_id` — один агент.** `registry.enroll` и `group_enrollment.submit` отказывают,
если для `host_id` уже есть агент (в любом статусе) без `instance_name`. Замена Python-агента на
.NET-агент на том же узле требует либо удаления старой записи, либо именованного экземпляра
(`instance_name`, оператор задаёт общий `host_id`). Миграция потока (`sequence`, закладки)
невозможна: новый агент получает новый `agent_id` и начинает с `sequence = 1` и пустого курсора.

13.3. **Пакет обновления для .NET.** `server/sli/agents/updates.py` → `upload` вызывает
`validate_payload`, требующий Python-файлы (`REQUIRED_FILES`), и допускает только каталоги
`sli_agent/`, `sli_collect/` и перечень общих файлов. ZIP-пакет с .NET-агентом сервер не примет.
Либо обновление .NET-агента идёт вне этого механизма (MSI/каналы Windows), либо серверу
нужен новый тип пакета — решение владельца; в этапе 1 сервер не меняется.

13.4. **Strict-поиск закладки.** Python использует `EvtSeek(..., EvtSeekStrict)` и отличает
пропавшую закладку (1168) от других ошибок. Публичный `EventLogReader.Seek(bookmark, offset)` в .NET
строгого режима не задаёт (проверить на Windows). Поэтому .NET-агент после перехода к закладке
читает якорное событие и сверяет `EventRecordID` сам; несовпадение трактуется как пропавшая
закладка (разрыв). Интеграционный тест сохранён, но ещё не выполнялся на Windows; подтверждение
поведения требует запуска теста на Windows.

13.5. **Источник `source_name` и `connect_address`.** Оба приходят из назначения модуля и
обязательны (`ADDCModule.__init__`). Как оператор их выбирает, в коде агента не описано —
это настройка на стороне сервера (`POST /api/v1/admin/agents/modules`).

13.6. **Сердцебиение.** При ревизионной политике (текущий сервер) `sli.heartbeat` не нужен.
Серверный разбор heartbeat (`receive_packet`) остаётся для совместимости. Решение «не
отправлять heartbeat» .NET-агент наследует.

13.7. **Числа с плавающей точкой** в `canonical` разрешены, но в протоколе не встречаются;
.NET-агент их не поддерживает (ошибка). Если формат изменится, нужна дословная реализация
`repr` для `float`.

13.9. **Закрыто: просроченный пакет не блокирует поток.** .NET-сервер возвращает
`agent_packet_expired`; .NET-агент долговечно отмечает разрыв, продвигает подтверждённую
последовательность и удаляет только соответствующий пакет. Следующий пакет объявляет `gap`,
сервер сохраняет последний период разрыва на модуль; «Состояние системы» показывает
«нет данных с <компьютера> за <период>». Лимит по возрасту очереди снят, лимит размера сохранён.
Подпись, хеши, порядок, курсоры и проверка повтора принятых пакетов сохраняются.
Для восстановления нужны обновлённый сервер с миграцией 348 и обновлённый агент.

13.8. **Поддержка RSA-ключей** серверу доступна, но агент использует только P-256; .NET-агент
тоже (меньше поверхности).

## 14. Как проверять совместимость

- `agent-dotnet/tests/vectors/` — эталонные данные, созданные **Python-реализацией**
  (`agent-dotnet/tools/make_vectors.py`): канонический JSON, подписанные пакеты, плохие пакеты с
  кодами ошибок, варианты квитанций с решением Python-очереди, разбор XML событий, запросы XPath
  для разных курсоров, сценарии модуля `sli.windows.ad-dc` шаг за шагом (вход чтения → пакет,
  курсоры, счётчики). Каталог событий для агента (`agent-dotnet/src/Sli.Agent.Core/Resources/`)
  создаётся тем же скриптом из `config/source_packs/dc.json` и `config/event_catalog.json`.
- `tests/unit/test_agent_dotnet_vectors.py` — (1) векторы совпадают с тем, что Python-код выдаёт
  сегодня (если контракт изменился, падает этот тест, а не .NET-агент в поле); (2) серверный код
  принимает векторы (`verify_packet`, `receive_packet`); (3) при `SLI_DOTNET_INTEROP_DIR`
  проверяет **пакеты и запрос регистрации, созданные .NET-агентом**: `receive_packet` (включая
  `dc_event_rows`) должен вернуть `committed`, повтор — `duplicate`, `parse_csr` — принять CSR.
- `agent-dotnet/tests/Sli.Agent.Tests` — .NET-тесты воспроизводят векторы побайтово и записывают
  пакеты для проверки (3). Тесты, которым нужна настоящая Windows (DPAPI, ACL, журнал событий с
  закладками), помечены `WindowsFact`/`WindowsAdminFact` и категорией `WindowsOnly`.
  Linux CI исключает их фильтром `Category!=WindowsOnly`. Эти тесты запускаются на Windows.
- `.github/workflows/agent-dotnet.yml` — сборка, тесты, проверка сервером, публикация
  self-contained; запускается только при изменениях, которые могут влиять на агент.
