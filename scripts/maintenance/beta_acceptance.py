"""Print the nine beta-1 acceptance checks for an installed SLI and LAB."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from http.client import HTTPException
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import UUID


ROOT = Path(__file__).resolve().parents[2]
MAX_JSON_BYTES = 8 * 1024 * 1024
REPORTS = ("ad.infrastructure", "ad.users.v2", "ad.computers.v6", "ad.gpo.v2")
LAB_SCENARIOS = range(1, 11)  # Beta catalog, shared with the existing LAB exercise results.
FIRST_LOGIN = ("На чистой установке откройте /api/auth/bootstrap в браузере, "
               "введите одноразовый код и убедитесь, что открылась главная .NET-сервера.")


class CheckFailed(Exception):
    """A fixed diagnostic that can be printed without exposing input data."""


class AuthorizationFailed(CheckFailed):
    """Preserve the authorization result when checking several rows."""


def require(condition, message):
    if not condition:
        raise CheckFailed(message)


def utc_now():
    return datetime.now(timezone.utc)


def stamp(value):
    result = datetime.fromisoformat(value)
    if result.utcoffset() is None:
        raise ValueError
    return result.astimezone(timezone.utc)


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def count(value, expected):
    return integer(value) and value == expected


def objects(value):
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError
    return value


def menu_entries():
    path = ROOT / "config" / "navigation_v3.json"
    return json.loads(path.read_text(encoding="utf-8"))["beta_entries"]


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def origin(value):
    # Validate before creating any request carrying an operator credential.
    try:
        parsed = urlsplit(value)
        parsed.port
        valid = (parsed.scheme == "https" and parsed.hostname
                 and parsed.username is None and parsed.password is None
                 and parsed.path in ("", "/") and not parsed.query and not parsed.fragment
                 and "#" not in value and "?" not in value and "\\" not in value
                 and value.isascii() and all(33 <= ord(char) < 127 for char in value))
    except ValueError:
        valid = False
    require(valid, "Укажите HTTPS-адрес SLI с доверенным сертификатом.")
    return f"https://{parsed.netloc.lower()}"


class Api:
    def __init__(self, base_url, token):
        self.base = origin(base_url)
        self.token = token
        self.opener = build_opener(ProxyHandler({}), NoRedirect())
        self.cookies = CookieJar()
        self.owns_session = False
        self.login_error = None

    def get(self, path, params=None):
        if self.login_error:
            raise AuthorizationFailed(self.login_error)
        return self._request(path, params=params)

    def login_owner(self, password):
        self.opener.add_handler(HTTPCookieProcessor(self.cookies))
        try:
            response = self._request("/api/auth/login", method="POST",
                                     body={"username": "platform-owner", "password": password})
            principal = response.get("principal")
            require(response.get("authenticated") is True and isinstance(principal, dict)
                    and principal.get("username") == "platform-owner" and principal.get("type") == "session"
                    and principal.get("role") == "admin"
                    and any(cookie.name == "adlog_session" and cookie.secure and cookie.value
                            for cookie in self.cookies), "SLI не подтвердил защищённую сессию владельца.")
        except CheckFailed as error:
            self.cookies.clear()
            self.login_error = f"Вход владельца не выполнен. {error}"
            raise CheckFailed(self.login_error) from None
        self.owns_session = True

    def logout_owner(self):
        if self.owns_session:
            try:
                response = self._request("/api/auth/logout", method="POST")
                require(response.get("status") == "ok", "Некорректное подтверждение выхода от SLI.")
            finally:
                self.owns_session = False
                self.cookies.clear()

    def _request(self, path, *, params=None, method="GET", body=None):
        require(path.startswith("/api/") and "?" not in path and "#" not in path, "Недопустимый путь API.")
        url = self.base + path
        if params:
            url += "?" + urlencode(params)
        headers = {"Accept": "application/json", "Accept-Language": "ru"}
        if method == "POST":
            headers["Origin"] = self.base
        elif not self.owns_session:
            require(self.token and all(33 <= ord(char) < 127 for char in self.token),
                    "Задайте SLI_ACCEPTANCE_OWNER_PASSWORD или SLI_OPERATOR_TOKEN с нужными правами.")
            headers["Authorization"] = "Bearer " + self.token
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = Request(url, headers=headers, method=method, data=None if body is None else json.dumps(body).encode())
        try:
            with self.opener.open(request) as response:
                raw = response.read(MAX_JSON_BYTES + 1)
                require(len(raw) <= MAX_JSON_BYTES, "Ответ SLI превышает допустимый объём.")
                payload = json.loads(raw)
        except HTTPError as error:
            error.close()
            if error.code == 401:
                raise AuthorizationFailed("HTTP 401. SLI требует аутентификацию.") from None
            if error.code == 403:
                raise AuthorizationFailed("HTTP 403. SLI отказал в доступе.") from None
            raise CheckFailed(f"HTTP {error.code}") from None
        except (HTTPException, URLError, OSError, ValueError):
            raise CheckFailed("Не удалось прочитать ответ SLI по HTTPS.") from None
        require(isinstance(payload, dict) and not payload.get("error"), "Ответ SLI содержит ошибку.")
        return payload


def installation(get, entry):
    require(entry.get("clean_debian_13") is True and entry.get("public_readme_only") is True,
            "Нужен замер установки на чистой Debian 13 по публичному README.")
    commands = entry.get("commands")
    require(integer(commands, 1) and commands <= 3 and count(entry.get("file_edits"), 0),
            "Требуются от одной до трёх команд и ноль ручных правок.")
    elapsed = (stamp(entry["ready_at"]) - stamp(entry["started_at"])).total_seconds()
    require(0 <= elapsed <= 1800 and stamp(entry["ready_at"]) <= utc_now(), "Установка вне окна 30 минут.")
    require(get("/api/health/ready").get("ready") is True, "Установленный SLI не подтвердил готовность PostgreSQL.")
    return f"Чистая Debian 13, команд {commands}, {elapsed:g} с, правок 0. PostgreSQL готов."


def first_login(entry):
    require(entry.get("one_time_code_used") is True and entry.get("dotnet_screen_opened") is True, FIRST_LOGIN)
    return "Куратор подтвердил одноразовый код и открытие главной с .NET-сервера."


def agent_collection(get, entry, agent_id):
    require(agent_id is not None and UUID(entry.get("id", "")) == agent_id,
            "Укажите идентификатор DC через --agent-id и наблюдение установки агента.")
    require(count(entry.get("msi_count"), 1) and count(entry.get("commands"), 1),
            "Нужен замер установки на DC с одним MSI и одной командой.")
    listing = get("/api/v1/overview", {"view": "agents"})["agent_collection"]
    observed = stamp(listing["checked_at_utc"])
    agents = [item for item in objects(listing["items"]) if item["id"] == str(agent_id)]
    require(len(agents) == 1 and agents[0]["state"] == "current" and agents[0]["connection"] == "online",
            "Текущий список SLI не показывает выбранный DC в рабочем состоянии.")
    started = stamp(entry["started_at"])
    require(any(stream["channel"] == "Security" and stream["state"] == "current"
                and started <= stamp(stream["last_import_at"]) <= observed
                for module in objects(agents[0]["modules"]) if module["module_id"] == "sli.windows.ad-dc"
                for stream in objects(module["channels"])),
            "SLI не подтвердил импорт журнала Security с выбранного DC.")
    collecting = stamp(entry["collecting_at"]) if "collecting_at" in entry else observed
    elapsed = (collecting - started).total_seconds()
    require(0 <= elapsed <= 600 and collecting <= observed, "Нет наблюдения начала сбора за 10 минут.")
    return f"Один MSI, одна команда, сбор через {elapsed:g} с. Сейчас DC подключён, Security импортирован."


def verify_gpo_domain(get, response, domain_id):
    coverage = response.get("coverage")
    graph = coverage.get("graph") if isinstance(coverage, dict) else None
    attributed = [item["domain_id"] for item in (response, coverage, graph)
                  if isinstance(item, dict) and item.get("domain_id") is not None]
    if attributed:
        require(all(count(value, domain_id) for value in attributed), "Снимок GPO относится к другому домену. Нужен LAB.")
        return
    domains = get("/api/v1/domains").get("items")
    require(isinstance(domains, list) and len(domains) == 1 and isinstance(domains[0], dict)
            and count(domains[0].get("id"), domain_id),
            "Снимок GPO не указывает домен. Для подтверждения LAB он должен быть единственным доступным доменом.")


def ad_reports(get, entry, agent, domain_id):
    unavailable = []
    for report in REPORTS:
        params = {"limit": 1, "tz": "UTC"}
        # GPO resolves domains from access grants, without a domain query parameter.
        if report != "ad.gpo.v2":
            params["domain"] = domain_id
        try:
            response = get(f"/api/v2/reports/{report}/data", params)
            ready = (response.get("report_key") == report and response.get("state") in ("ok", "partial")
                     and bool(objects(response.get("items"))))
        except AuthorizationFailed:
            raise
        except (CheckFailed, ValueError):
            unavailable.append(report)
        else:
            if not ready:
                unavailable.append(report)
            elif report == "ad.gpo.v2":
                verify_gpo_domain(get, response, domain_id)
    require(not unavailable, "В SLI нет строк или не загрузилось: " + ", ".join(unavailable))
    require("started_at" in agent, "Нужно время начала установки агента для проверки 15 минут.")
    observed = utc_now()
    if entry:
        historical = entry["rows"]
        require(all(integer(historical.get(report), 1) for report in REPORTS),
                "В раннем наблюдении нужны строки каждого из четырёх отчётов AD.")
        observed = stamp(entry["observed_at"])
    elapsed = (observed - stamp(agent["started_at"])).total_seconds()
    require(0 <= elapsed <= 900 and observed <= utc_now(), "Нет наблюдения строк AD за 15 минут.")
    return f"Четыре отчёта содержат строки, проверены через {elapsed:g} с после запуска установки агента."


def telegram_accepted(get, finding, started, next_attempt):
    params = {"finding_id": finding, "days": 30, "channel": "telegram", "status": "accepted"}
    cursors = set()
    while True:
        response = get("/api/v1/notification-channels/workspace", params)
        for row in objects(response["items"]):
            if (not count(row.get("finding_id"), finding) or row.get("channel") != "telegram"
                    or row.get("object_kind") != "semantic_finding" or row.get("state") != "accepted"):
                continue
            created = stamp(row["created_at"])
            if started <= created <= utc_now() and (next_attempt is None or created < next_attempt):
                return True
        if response.get("has_more") is not True:
            return False
        cursor = response.get("next_cursor")
        if not isinstance(cursor, str) or not cursor or cursor in cursors:
            return False
        cursors.add(cursor)
        params["cursor"] = cursor


def exercises(get, entry):
    require(entry, "Нужны наблюдения главной по каждому сценарию LAB.")
    runs = objects(entry)
    require(sorted(row["scenario"] for row in runs if integer(row.get("scenario"), 1)) == list(LAB_SCENARIOS)
            and len(runs) == len(LAB_SCENARIOS), "Нужен один результат на каждый сценарий каталога LAB.")
    starts = {row["scenario"]: stamp(row["started_at"]) for row in runs}
    failed = []
    longest = 0
    for row in sorted(runs, key=lambda item: item["scenario"]):
        try:
            finding = row["finding_id"]
            started, observed = starts[row["scenario"]], stamp(row["on_home_at"])
            elapsed = (observed - started).total_seconds()
            title = row.get("title")
            valid = (integer(finding, 1) and finding <= 2**63 - 1 and 0 <= elapsed <= 300
                     and observed <= utc_now() and count(row.get("groups"), 1)
                     and isinstance(title, str) and re.search("[А-Яа-яЁё]", title)
                     and all(isinstance(row.get(key), str) and row[key].strip() not in ("", "—", "-")
                             for key in ("what", "action")))
            if valid:
                other_attempts = [starts[other["scenario"]] for other in runs if other is not row
                                  and other.get("finding_id") == finding]
                next_attempt = min((at for at in other_attempts if at > started), default=None)
                if started not in other_attempts and telegram_accepted(get, finding, started, next_attempt):
                    longest = max(longest, elapsed)
                    continue
        except AuthorizationFailed:
            raise
        except (CheckFailed, KeyError, TypeError, ValueError, OverflowError):
            pass
        failed.append(str(row["scenario"]))
    require(not failed, "Главная, группировка, тексты, время или Telegram не подтверждены для сценариев "
            + ", ".join(failed) + ".")
    return f"Все {len(runs)} сценариев, максимум {longest:g} с. Telegram принял сообщения."


def quiet(entry, rehearsal):
    require(entry.get("clean_install_without_attacks") is True,
            "Нужен замер главной на чистой установке до учений.")
    observed = stamp(entry["observed_at"])
    require(observed <= utc_now() and all(observed < stamp(row["started_at"]) for row in objects(rehearsal)),
            "Наблюдение тихого состояния должно предшествовать учениям.")
    hygiene, other = entry.get("hygiene"), entry.get("other")
    require(integer(hygiene) and integer(other), "Нужны оба счётчика проблем на тихой установке.")
    evidence = f"До учений: проблем гигиены AD {hygiene}, прочих {other}."
    require(hygiene <= 10 and other == 0, evidence + " Требуется не более 10 и 0 соответственно.")
    return evidence


def storage(get, entry):
    require(entry, "Нужны ежедневные размеры PostgreSQL после окончания окна хранения.")
    start = stamp(entry["retention_elapsed_at"])
    measurements = [(stamp(row["at"]), row["bytes"]) for row in objects(entry["samples"])]
    lifecycle = get("/api/storage/lifecycle")
    require(lifecycle.get("backend") == "postgres" and isinstance(lifecycle.get("latest_snapshot"), dict),
            "SLI не вернул последний замер PostgreSQL.")
    latest = lifecycle["latest_snapshot"]
    current = (stamp(latest["captured_at"]), latest["database_bytes"])
    if current not in measurements:
        measurements.append(current)
    measurements.sort()
    first_at, first_bytes = measurements[0]
    last_at, last_bytes = current
    require(measurements[-1] == current and last_at <= utc_now() and first_at >= start
            and all(integer(size, 1) for _, size in measurements)
            and (utc_now().date() - last_at.date()).days <= 1,
            "Нужны сопоставимые замеры после окна хранения и текущий замер SLI.")
    days = sorted({at.date() for at, _ in measurements})
    require(last_at - first_at >= timedelta(days=7)
            and all((end - begin).days == 1 for begin, end in zip(days, days[1:]))
            and len({at for at, _ in measurements}) == len(measurements),
            "Нужны замеры без пропусков по дням за 7 суток или дольше.")
    # Reject an upward trend even if a single late dip brings the total below the first reading.
    offsets = [(at - first_at).total_seconds() for at, _ in measurements]
    average = sum(offsets) / len(offsets)
    trend = sum((offset - average) * (size - first_bytes)
                for offset, (_, size) in zip(offsets, measurements))
    evidence = (f"{first_at.date()} — {last_at.date()}, {len(days)} дней с замерами, "
                f"{first_bytes} → {last_bytes} байт.")
    require(last_bytes <= first_bytes and trend <= 0, "Объём PostgreSQL растёт. " + evidence)
    return evidence


def live_commit(get):
    health = get("/api/health")
    commit = health.get("runtime_identity", {}).get("git_commit")
    require(health.get("status") == "ok" and isinstance(commit, str) and re.fullmatch("[0-9a-f]{40}", commit),
            "Установленный SLI не сообщает идентификатор сборки.")
    return commit


def upgrade(get, entry):
    require(entry.get("command") == "apt upgrade" and count(entry.get("exit_code"), 0)
            and count(entry.get("manual_steps"), 0), "Нужен результат apt upgrade без ручных шагов.")
    before, after = entry.get("before_commit"), entry.get("after_commit")
    require(isinstance(before, str) and re.fullmatch("[0-9a-f]{40}", before) and before != after
            and after == live_commit(get) and get("/api/health/ready").get("ready") is True,
            "Нужны две разные сборки, текущая сборка должна совпадать с результатом обновления.")
    digest = entry.get("before_sha256")
    require(integer(entry.get("records"), 1) and isinstance(digest, str) and re.fullmatch("[0-9a-f]{64}", digest)
            and digest == entry.get("after_sha256"), "Нужна совпадающая контрольная сумма данных до и после.")
    return f"APT завершился, сборка сменилась, контрольная сумма {entry['records']} записей совпала."


def menu(get, entry):
    require(isinstance(entry.get("pages"), dict), "Обойдите в браузере меню беты под владельцем.")
    require(entry.get("commit") == live_commit(get), "Обход меню нужен для установленной сборки.")
    pages = entry["pages"]
    expected = menu_entries()
    failed = []
    for key in expected:
        page = pages.get(key, {})
        if (not isinstance(page, dict) or not count(page.get("load_errors"), 0)
                or not count(page.get("completeness_labels"), 0)
                or not (page.get("data") is True
                        or page.get("data") is False and count(page.get("action_phrases"), 1))):
            failed.append(key)
    require(not failed, "Не пройдены пункты меню: " + ", ".join(failed))
    require(set(pages) == set(expected), "В меню наблюдались пункты вне состава беты.")
    return f"Пунктов {len(expected)}. На каждом данные или одно действие, ошибок и меток полноты 0."


CHECK_NAMES = ("Установка", "Первый вход владельца", "Агент на DC", "Экраны AD", "Учения LAB",
               "Тихое состояние", "Объём PostgreSQL", "Обновление", "Обход меню")


def run_checks(get, observations, domain_id, agent_id, *, progress=lambda name: None):
    def entry(key):
        value = observations.get(key, {})
        if not isinstance(value, dict):
            raise ValueError
        return value

    checks = (
        lambda: installation(get, entry("install")),
        lambda: first_login(entry("first_login")),
        lambda: agent_collection(get, entry("agent"), agent_id),
        lambda: ad_reports(get, entry("ad"), entry("agent"), domain_id),
        lambda: exercises(get, observations.get("exercises", [])),
        lambda: quiet(entry("quiet"), observations.get("exercises", [])),
        lambda: storage(get, entry("storage")),
        lambda: upgrade(get, entry("upgrade")),
        lambda: menu(get, entry("menu")),
    )
    rows = []
    for name, check in zip(CHECK_NAMES, checks):
        progress(name)
        try:
            rows.append((True, check()))
        except CheckFailed as error:
            rows.append((False, str(error)))
        except (KeyError, TypeError, ValueError, AttributeError, OverflowError, OSError):
            rows.append((False, "Наблюдение или ответ SLI не соответствует ожидаемому формату."))
    return rows


def table(rows):
    lines = ["| Проверка | Итог | Доказательство |", "|---|---|---|"]
    for number, (name, (passed, evidence)) in enumerate(zip(CHECK_NAMES, rows), 1):
        lines.append(f"| {number}. {name} | {'Зелёная' if passed else 'Красная'} | {evidence} |")
    lines.extend(("", f"{sum(passed for passed, _ in rows)} из {len(CHECK_NAMES)}"))
    return "\n".join(lines)


def read_observations(file, base, domain_id):
    if not file:
        return {}
    if file == "-":
        raw = sys.stdin.buffer.read(MAX_JSON_BYTES + 1)
    else:
        with Path(file).open("rb") as stream:
            raw = stream.read(MAX_JSON_BYTES + 1)
    require(len(raw) <= MAX_JSON_BYTES, "Файл наблюдений слишком велик.")
    value = json.loads(raw)
    require(isinstance(value, dict) and value.get("origin") == base and count(value.get("domain_id"), domain_id),
            "Наблюдения должны относиться к указанному адресу SLI и домену LAB.")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog=(
        "Set SLI_ACCEPTANCE_OWNER_PASSWORD to sign in as platform-owner. "
        "SLI_OPERATOR_TOKEN accepts an API key when that key has access to all checks."
    ))
    parser.add_argument("--api-url", required=True, help="HTTPS origin of installed SLI")
    parser.add_argument("--domain-id", required=True, type=int, help="SLI domain ID for LAB")
    parser.add_argument("--agent-id", type=UUID, help="Installed LAB DC agent UUID")
    parser.add_argument("--observations", help="Curator's observations in JSON, or - for stdin")
    args = parser.parse_args(argv)
    if args.domain_id <= 0:
        parser.error("--domain-id must be positive")
    owner_password = os.environ.get("SLI_ACCEPTANCE_OWNER_PASSWORD")
    try:
        api = Api(args.api_url, "" if owner_password else os.environ.get("SLI_OPERATOR_TOKEN", ""))
    except CheckFailed as error:
        parser.error(str(error))
    try:
        observations = read_observations(args.observations, api.base, args.domain_id)
    except (OSError, ValueError, CheckFailed) as error:
        message = str(error) if isinstance(error, CheckFailed) else "Не удалось прочитать JSON наблюдений."
        print(message, file=sys.stderr)
        observations = {}
    if owner_password:
        try:
            api.login_owner(owner_password)
        except CheckFailed as error:
            print(error, file=sys.stderr)
    try:
        rows = run_checks(api.get, observations, args.domain_id, args.agent_id,
                          progress=lambda name: print(f"Проверка «{name}»…", file=sys.stderr, flush=True))
    finally:
        if owner_password:
            try:
                api.logout_owner()
            except CheckFailed as error:
                print(f"SLI не подтвердил выход из сессии проверки. {error}", file=sys.stderr)
    print(table(rows))
    return 0 if all(passed for passed, _ in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
