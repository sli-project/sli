## T021 — системные подписи выбранного языка

- RU/EN: подписи источников настроек, известные ошибки доменов/контроллеров и встроенные источники первичной настройки переводятся при отображении; сохранены исходные значения неизвестных источников.
- RU/EN: VPN Accounting и состояние/фазы сбора используют коды сообщений; добавлены проверки английских системных подписей на существующих экранах.
- RU/EN: settings source labels, known setup validation errors, builtin setup sources, VPN Accounting and collection presentation follow the selected locale without rewriting source evidence.

# Changelog

Все заметные изменения проекта SLI Platform фиксируются в этом файле.
Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
проект следует [Semantic Versioning](https://semver.org/lang/ru/).

Первая публичная версия будет `1.0.0`. Текущая версия разработки — `0.1.0`;
релизы и теги пока не выпускаются.

## [Unreleased]

### Added

- Файловые серверы: таблица назначенных ресурсов, сохранённые наблюдения 4670,
  полноэкранный просмотр SMB/NTFS ACL и сравнение совместимых снимков. Фильтры,
  период и контекст возврата сохраняются; доступны страницы по 25/50/100/200 строк.
  Число наблюдений в агрегате отделено от числа строк и файлов; неполные или
  отсутствующие ACL не интерпретируются как удалённые права.
- File servers: resource overview, retained 4670 observations, full-page SMB/NTFS
  permissions and compatible snapshot comparison, with preserved filters and
  25/50/100/200-row pages. Missing evidence stays distinct from an empty ACL;
  opening reports does not change audit policy or start filesystem scans.

- Вкладка Sigma: выбор доступного scope без ручного SHA, точный допуск версии
  и отдельные TEST/runtime-счётчики. Ограниченный reader названия/назначения
  привязан к точной ревизии и scope; автоматический допуск не добавлен.
- Лицензия Apache-2.0 (`LICENSE`), `CONTRIBUTING.md`, `SECURITY.md`,
  `CODE_OF_CONDUCT.md`, `CODEOWNERS` и публичный `README.md`.
- Страница настроек платформы в веб-интерфейсе.
- Генераторы демонстрационных данных (`scripts/demo/`): синтетические события,
  демонстрационный пакет Active Directory и нагрузочный профиль.
- Каркас отчётов, руководства по добавлению отчётов и источников, реестр
  маршрутов API и модели представления отчётов v4.
- Дизайн-система фронтенда и описание архитектурных решений в `docs/adr/`.
- Страница «Компьютеры» системного раздела, агрегат тепловой карты, индексы
  и предрасчёт связей для ускорения панели и поиска событий.
- Рабочий процесс GitHub Actions `pr-gate` (`source`, `tests`, `frontend`).

### Changed

- Первичная настройка проверяет сбор по агентам и точным назначениям источников,
  а не по старой блокировке серверного сборщика; ошибки и история остаются различимыми.
- First-run setup checks agent collection and exact source assignments instead of
  legacy server admission blocks, preserving errors and historical evidence.

- Допуск версий политик показывает название правила и дату регистрации версии;
  технические идентификаторы сохранены в подробностях.
- Policy version admission shows the rule title and version registration date;
  technical identifiers remain available in details.

- Backend разложен по доменам `server/sli/<domain>/`, тесты расположены
  по тем же доменам; крупные модули (хранилище, отчёты, поиск событий,
  сбор данных) разделены на части.
- Единственный движок хранения — Storage V2 на PostgreSQL; жизненный цикл
  хранилища выполняется отдельным воркером.
- Обновлены пути и ссылки в документации для публичного снимка.
- Локальные пути и параметры окружения вынесены из кода в конфигурацию.

### Removed

- Переходный слой Storage V1 (ветки V1 в маршрутах, импортёре и outbox):
  остался только Storage V2.
- Страницы миграции базы данных из веб-интерфейса.

### Security

- Updater больше не исполняет код из входящего source ZIP до проверки издателя:
  пакеты собираются по явному перечню файлов и проверяются по Ed25519-подписи,
  внешнему trust store, размерам, хешам и путям до любого исполнения; старое
  применение source ZIP и восстановление произвольного backup заблокированы.
  Релиз-процесс и установка подписанных пакетов пока не включены.

### Fixed

- Установщик Debian показывает точные коды отказов при проверке служб,
  диска резервного копирования и сохранённых файлов восстановления.
- T068: шаг контроллеров первичной настройки показывает состояние зарегистрированных агентов из того же снимка health, что источники и сбор; legacy-настройки целей отделены от состояния агента. Unknown и архивность домена не подменяются.
- T068: the setup controller step uses registered-agent observations shared with source/collection health; legacy target settings remain separate. Unknown state and domain archive metadata are preserved.

- На завершённом шаге доменов первичной настройки форма добавления свёрнута;
  раскрытие сохраняет поля и существующие права управления.
- The completed domain setup step collapses the add form without changing its
  fields or management permissions.

- Повторные запросы отчёта при обновлении страницы.
- Ряд замечаний по результатам приёмки на тестовом стенде.
- Нестабильный по времени тест запуска PowerShell в CI.
- Повторная настройка сохраняет стартовый таймаут служб резервного копирования,
  если файлы юнитов совпадают с проверенной копией принятого выпуска.

