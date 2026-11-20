# Установка сервера

[English version](SERVER_INSTALL.en.md) · [Установка агента](AGENT_INSTALL.ru.md)

Инструкция предназначена для изолированной оценки на Linux-хосте Docker.
Нужны Docker Engine/Compose и доверенный checkout или выпуск SLI.
PostgreSQL 18 и ClickHouse обязательны.
[deploy/dev](../../deploy/dev/docker-compose.yml) предназначен только для разработки.

## Как получить пакет поставки

Получите у поставщика через согласованный канал выпуска полный **подписанный
и запечатанный офлайн-комплект** нужной версии и SHA исходников.
Артефакт Actions `sli-unsigned-<SHA>` требует сборки образов и офлайн-подписи
владельцем ключа; покупателю он не подходит как готовая поставка.

Поместите комплект целиком в `/release/kit`, вне `/srv/sli`, секретов и резервных
копий. Отдельным доверенным каналом получите внешний JSON trust store
`/etc/sli/trust/release.json` и доверенные проверяющие скрипты/host-libs; нельзя
устанавливать доверие к ним по описи из самого комплекта. На целевом Linux amd64
хосте заранее нужны Docker/Compose и системный `python3` (Python ≥3.11) с glibc:
Python 3.13 Debian 13 и Python 3.12 Ubuntu 24.04 подходят. Комплект содержит
отдельные нативные библиотеки для CPython 3.11–3.14; Python 3.14 на хосте не нужен.
Сверьте SHA-256 `KIT_INVENTORY.json` со значением поставщика из отдельного
доверенного канала: сама опись не подписана.

```sh
sha256sum /release/kit/KIT_INVENTORY.json
export PYTHONPATH=/release/kit/host-libs/python$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'):/release/kit/source
export PYTHONDONTWRITEBYTECODE=1
python3 /release/kit/verify_offline_kit.py --kit /release/kit \
  --trust-store /etc/sli/trust/release.json
python3 - <<'PY'
from pathlib import Path
from server.sli.release_package import verify_package
verify_package(Path('/release/kit/packages/install.zip'), Path('/etc/sli/trust/release.json'))
print('signature_verified')
PY
```

Обе проверки должны завершиться с кодом 0. Первая проверяет полноту и SHA-256,
но возвращает `authenticated=false`; вторая проверяет подпись Ed25519,
политику ключа и подписанное содержимое. Для обновления также проверьте
`packages/update.zip`. На целевом сервере сборку не запускайте; установка
повторно проверяет подпись и выполняется по
офлайн-процедуре.
Разделы ниже описывают оценочный запуск из checkout.

## Офлайн-комплект для оценки без подписи

Штатный `build_offline_kit.sh` без отдельного подписания выдаёт комплект
**«для оценки, без подписи»** (`signing: evaluation-unsigned` в inventory).
В нём есть три образа, `packages/install.zip`, эта инструкция и `START_HERE.md`.
Это комплект для новой изолированной оценки; он не подтверждает подпись
поставщика и не предназначен для обновления существующей установки.

1. Подготовьте Linux amd64, Docker Engine/Compose и Python >=3.11 с glibc.
   Поместите комплект в `/release/kit`, вне runtime и секретов. Получите
   SHA-256 `KIT_INVENTORY.json` от поставщика отдельным доверенным каналом.
   Сравните его с `sha256sum /release/kit/KIT_INVENTORY.json` и подставьте
   ожидаемые 64 символа вместо `<EXPECTED_SHA256>` в командах ниже.
   Контрольная сумма из самого комплекта не устанавливает доверие.
2. Проверьте inventory и SHA-256 всех файлов. Оба режима проверки возвращают
   `authenticated=false`; SHA-256 подтверждает целостность, но не подпись.

   ```sh
   export PYTHONPATH=/release/kit/host-libs/python$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'):/release/kit/source
   export PYTHONDONTWRITEBYTECODE=1
   python3 /release/kit/verify_offline_kit.py --kit /release/kit \
     --evaluation --inventory-sha256 <EXPECTED_SHA256>
   ```

   Продолжайте только при exit 0 и `status=complete`. Без `--evaluation`
   проверка и установщик отвергают unsigned-комплект. Этот флаг не отменяет
   проверку inventory, образов, миграций, TLS или запрет повторного использования данных.
3. Подготовьте TLS по [процедуре ниже](#подготовка-tls): сертификат организации
   или локальный самоподписанный CA для оценки. SAN должны включать клиентское
   имя/IP, DNS `api` и IP `127.0.0.1` для указанного ниже `--health-url`.
   Не выводите приватный ключ. Выберите новое пустое хранилище `/srv/sli-eval`
   с достаточным свободным местом и доступный доверенный HTTPS endpoint.
   Compose project фиксирован как `sli`: на хосте не должно быть контейнеров
   и томов этого проекта. Установщик создаёт секреты, backups и новые тома сам;
   заранее не создавайте тома из раздела запуска checkout ниже.
4. После проверки загрузите инфраструктурные образы и запустите установщик
   из `source` с правами root (все файлы TLS — подготовленные внешние файлы).
   Для доступа с другого ПК явно задайте несекретные `SLI_BIND_ADDRESS` и
   `SLI_HTTPS_PORT`; по умолчанию слушается loopback.

   ```sh
   docker load -i /release/kit/images/postgres.tar
   docker load -i /release/kit/images/clickhouse.tar
   cd /release/kit/source
   export SLI_INSTALL_DOMAIN=example.invalid
   export SLI_HEALTH_URL=https://api:8443/api/health/ready
   python3 deploy/linux/sli_install.py \
     --package /release/kit/packages/install.zip --kit /release/kit \
     --evaluation --inventory-sha256 <EXPECTED_SHA256> --runtime /srv/sli-eval \
     --compose deploy/linux/docker-compose.yml \
     --health-url https://127.0.0.1:8443/api/health/ready \
     --ca-file /etc/sli/tls/tls_ca --tls-certificate /etc/sli/tls/tls_certificate \
     --tls-key /etc/sli/tls/tls_key
   ```

   Сборка и загрузка из сети на целевом хосте не выполняются. Установщик
   проверяет архив и серверный образ до изменения runtime, запускает migrator
   и проверяет health/HTTPS. При успехе `state/installed.json` сохраняет
   `signing=evaluation-unsigned` и `authenticated=false`. Используйте защищённый
   `/srv/sli-eval/secrets/platform_owner_password` для входа как `platform-owner`
   по адресу `https://<клиентское-имя-или-IP>:8443/app`;
   пароль не печатайте в журнал. При `recovery_required` сохраните тома и разберите
   сбой: автоматический повтор свежей установки не разрешён.

Для подписанной поставки выполняйте предыдущую процедуру с внешним trust store;
подпись создаётся владельцем отдельно в офлайн-среде. Оценочный флаг не разрешает
неподписанные обновления. Нижеследующие разделы относятся к запуску из checkout.

## Подготовка TLS

Выполните после проверки комплекта, с правами root, вне runtime и kit.
Сохраните выбранный `PYTHONPATH` и `PYTHONDONTWRITEBYTECODE=1` из проверки.
Если сертификата организации нет, для оценки используйте штатную генерацию
локального самоподписанного CA и подписанного им серверного сертификата:

```sh
python3 /release/kit/source/deploy/linux/sli_secrets.py ensure \
  --directory /etc/sli/tls --tls-name example.invalid --tls-name api --tls-name 127.0.0.1
```

Замените `example.invalid` на клиентское DNS-имя или IP; при доступе обоими
способами добавьте оба через `--tls-name`. Скрипт создаёт защищённые
`tls_ca`, `tls_certificate`, `tls_key` и независимые секреты core; установщик
импортирует только три файла TLS. Повторный запуск сохраняет существующий
сертификат: изменение `--tls-name` не добавляет SAN в ранее созданный файл.
При смене адреса используйте новый защищённый каталог, сохранив прежние файлы.
Приватные ключи и пароли не выводятся и не передаются на клиентский ПК.

Если есть сертификат организации, вместо генерации поместите цепочку
доверенного CA, серверный сертификат (с промежуточными сертификатами) и
соответствующий PEM-ключ без пароля в новый защищённый каталог:

```sh
install -d -m 0700 /etc/sli/tls
install -m 0600 /secure/input/ca.pem /etc/sli/tls/tls_ca
install -m 0600 /secure/input/server.pem /etc/sli/tls/tls_certificate
install -m 0600 /secure/input/server.key /etc/sli/tls/tls_key
```

В сертификате обязательны DNS SAN `api`, IP SAN `127.0.0.1` и SAN клиентского
адреса; IP должен быть IP SAN, а не DNS SAN. Внутри контейнера healthcheck
обращается к `https://api:8443/api/health/ready`, установщик на хосте — к
`https://127.0.0.1:8443/api/health/ready`. Для другого `--health-url` сертификат
должен покрывать его адрес; проверку TLS не отключайте.

При наличии системного OpenSSL проверьте публичный сертификат, не печатая ключ
(установщик в любом случае проверяет TLS):

```sh
openssl x509 -in /etc/sli/tls/tls_certificate -noout -ext subjectAltName
openssl verify -CAfile /etc/sli/tls/tls_ca /etc/sli/tls/tls_certificate
```

Для самоподписанного CA передайте **только публичный** `/etc/sli/tls/tls_ca`
на клиентский ПК доверенным каналом и импортируйте в доверенные корневые
центры сертификации ОС/браузера (Windows: «Установить сертификат» →
«Текущий пользователь» → «Доверенные корневые центры сертификации»).
Для CA организации убедитесь, что его цепочке уже доверяют. После установки
откройте `https://<клиентское-имя-или-IP>:8443/app` (при изменённом порте —
выбранный `SLI_HTTPS_PORT`); адрес должен совпадать с SAN.

## Подготовка хоста

1. Выделите постоянное хранилище и место для PostgreSQL, истории и тёплого слоя,
   файловых доказательств SLI, полного резервного набора и проверки восстановления.
   Секреты установки и резервные копии храните вне checkout/контекста сборки.
2. Подготовьте защищённые файлы секретов: `postgres_password`,
   `migration_password`, `runtime_password`, `platform_owner_password`,
   `semantic_password`, `storage_password`, `history_password`, `warm_password`,
   `tls_certificate`, `tls_key` и `tls_ca`. Используйте независимые
   сгенерированные пароли; пароль владельца платформы — не короче 12 символов.
   Соблюдайте требования runbook к правам файлов, чтению из контейнеров и LF
   для пароля ClickHouse.
3. По процедуре подготовки TLS выше подготовьте сертификат для выбранного клиентского имени и внутреннего
   имени сервиса `api`, а также доверенную цепочку CA. В примерах
   `example.invalid` — шаблон: замените его именем тестовой установки.
   Ограничьте опубликованный API и настройте прокси/межсетевой экран по
   инструкции аутентификации и прокси.
4. Подготовьте каталог резервных копий и права общей группы по
   инструкции резервного копирования.
   Секреты не должны попадать в аргументы команд, логи или переменные окружения.

## Запуск новой тестовой установки

Из корня checkout на Linux-хосте задайте несекретные параметры. Три внешних
тома ниже создавайте **только для новой пустой тестовой установки**. При наличии
данных сохраните/восстановите тома и файловые данные SLI по runbook;
не заменяйте их пустыми томами.

```sh
export SLI_SECRETS_DIR=/srv/sli/secrets
export SLI_BACKUP_DIR=/srv/sli/backups
export SLI_INSTALL_DOMAIN=example.invalid
export SLI_HEALTH_URL=https://api:8443/api/health/ready
export SLI_HISTORY_DATA_VOLUME=sli-eval-history
export SLI_HISTORY_BACKUPS_VOLUME=sli-eval-history-backups
export SLI_WARM_CLICKHOUSE_VOLUME=sli-eval-warm

docker volume create sli-eval-history
docker volume create sli-eval-history-backups
docker volume create sli-eval-warm
docker compose -p sli -f deploy/linux/docker-compose.yml up --build -d
docker compose -p sli -f deploy/linux/docker-compose.yml ps -a
docker compose -p sli -f deploy/linux/docker-compose.yml logs migrate
```

В последующих командах используйте тот же проект, настройки и файлы Compose.
По умолчанию API слушает loopback; для удалённого доступа явно задайте
`SLI_BIND_ADDRESS` и `SLI_HTTPS_PORT`. Перед запуском API/воркеров migrator
проверяет baseline, контрольные суммы неизменяемых SQL и точный ledger.
Не редактируйте применённые SQL и не исправляйте записи миграций вручную.

## Проверка и эксплуатация

Требуются код завершения `migrate` 0 и healthy-состояние сервисов данных,
API и воркеров. Проверьте `/api/health/ready` через доверенный HTTPS CA
на настроенном адресе, затем войдите как владелец платформы с подготовленным
паролем. Проверяйте безопасные статусы без вывода исходных записей и секретов.

Для новых томов ClickHouse создайте и проверьте
[схему истории](../../config/clickhouse/002_permanent_fact_history.sql) и схему
тёплого слоя выбранного выпуска через его проверенную процедуру настройки хранения.
Healthy-состояние контейнера само по себе не подтверждает готовность схем и истории.

Сбор изначально отключён. Зарегистрируйте агентов и отдельно включите разрешённые
плагины/модули. Допуски удаления и копирования в тёплый слой остаются закрытыми.
ClickHouse обязателен; недоступную историю нельзя трактовать как отсутствие
активности. Проверьте полный резервный набор и восстановление, прежде чем
полагаться на recovery; запуск сервисов сам по себе не является приёмкой.

Для обновления нужны подписанный пакет, доверенная утилита обновления,
внешнее хранилище доверенных ключей и проверенная опись установки. Сохраняйте journal/checkpoint для resume или rollback. Перенос
существующей БД выполняйте по инструкции восстановления.
Для плановой остановки тестовой установки выполните
`docker compose -p sli -f deploy/linux/docker-compose.yml stop`;
сохраните все тома, резервные копии и доказательства.
