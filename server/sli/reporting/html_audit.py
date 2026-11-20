from __future__ import annotations

import ast
import hashlib
import html as html_lib
import ipaddress
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable

from server.sli.core.paths import ROOT
from server.sli.reporting.ui_navigation import source_event_id_for_navigation

DEFAULT_BASE_URL = "http://127.0.0.1:8080"
DEFAULT_TIMEOUT_SECONDS = 20
DEFAULT_SLOW_MS = 3000
_AUDIT_FAILED_LOGON_EVENT_ID = source_event_id_for_navigation("failed_logon")


@dataclass(frozen=True)
class HtmlPageSpec:
    page_id: str
    url: str
    title: str
    category: str
    lifecycle: str = "active"
    safe_get: bool = True
    expected_status: tuple[int, ...] = (200,)
    slow_ms: int = DEFAULT_SLOW_MS
    notes: str = ""


REGISTERED_PAGES: tuple[HtmlPageSpec, ...] = (
    HtmlPageSpec("home", "/", "Главная панель", "static_app"),
    HtmlPageSpec("event_details", f"/reports/event-details.html?event_id={_AUDIT_FAILED_LOGON_EVENT_ID}&channel=Security&limit=20", "Event details", "events"),
    HtmlPageSpec("event_search", "/reports/search.html?limit=20&order=desc", "Поиск событий", "events"),
    HtmlPageSpec("event_search_deep", "/reports/search-deep.html?q=__html_audit_no_match__&limit=20&order=desc", "Глубокий поиск событий", "events", slow_ms=8000),
    HtmlPageSpec("account_timeline", "/reports/account-timeline.html?q=__html_audit_no_match__&limit=20&order=asc", "История учётной записи", "events"),
    HtmlPageSpec("entity_details", "/reports/entity-details.html?limit=20&order=desc", "Entity details", "entities"),
    HtmlPageSpec("collector_health", "/reports/collector-health.html", "Состояние сбора", "operations"),
    HtmlPageSpec("autocollection", "/reports/autocollection.html", "Состояние автосбора", "operations"),
    HtmlPageSpec("system_health", "/reports/system-health.html", "Состояние системы", "operations"),
    HtmlPageSpec("storage_health", "/reports/storage-health.html?deep=0", "Storage Health", "operations"),
    HtmlPageSpec("db_status", "/reports/db-status.html", "DB Backend Status", "database"),
    HtmlPageSpec("diagnostics", "/reports/diagnostics.html?run_checks=0", "Диагностика", "operations"),
    HtmlPageSpec("investigation", "/reports/investigation.html?limit=20", "Рабочее место расследования", "security"),
    HtmlPageSpec("findings", "/reports/findings.html?limit=20&refresh=0", "Findings", "security"),
    HtmlPageSpec("security_monitor", "/reports/security-events-monitor.html?period=24h&limit=50", "ИБ-мониторинг событий", "security"),
    HtmlPageSpec("ai_redaction", "/reports/ai-redaction-preview.html?redaction_level=strict&limit=10", "AI redaction preview", "ai"),
    HtmlPageSpec("ai_prompt", "/reports/ai-prompt-preview.html?redaction_level=strict&limit=10", "AI prompt preview", "ai"),
    HtmlPageSpec("ai_reports", "/reports/ai-reports.html?limit=20", "AI-отчеты", "ai"),
    HtmlPageSpec("ai_analysis_empty", "/reports/ai-analysis.html", "AI-отчет", "ai"),
    HtmlPageSpec("role_overview", "/reports/role-overview.html", "Ролевые представления", "navigation"),
    HtmlPageSpec("ui_navigation", "/reports/ui-navigation.html", "Карта навигации", "navigation"),
)


class _HtmlInspector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self._in_title = False
        self.links: list[str] = []
        self.resources: list[str] = []
        self.forms: list[dict[str, str]] = []
        self.tags = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags += 1
        data = {str(k).lower(): str(v or "") for k, v in attrs}
        if tag.lower() == "title":
            self._in_title = True
        elif tag.lower() == "a" and data.get("href"):
            self.links.append(data["href"])
        elif tag.lower() in {"script", "img", "link"}:
            value = data.get("src") or data.get("href")
            if value:
                self.resources.append(value)
        elif tag.lower() == "form":
            self.forms.append({"method": data.get("method", "get").lower(), "action": data.get("action", "")})

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)

    @property
    def title(self) -> str:
        return " ".join(" ".join(self.title_parts).split())


def _is_loopback_base_url(base_url: str) -> bool:
    parsed = urllib.parse.urlparse(base_url)
    host = (parsed.hostname or "").strip().lower()
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _read_url(url: str, timeout_seconds: int) -> dict[str, Any]:
    started = time.perf_counter()
    request = urllib.request.Request(url, headers={"User-Agent": "SecurityLogIntelligence-HTML-Audit/2.0", "Accept": "text/html,application/xhtml+xml"})
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body = response.read()
            status_code = int(response.status)
            headers = dict(response.headers.items())
            error = None
    except urllib.error.HTTPError as exc:
        body = exc.read()
        status_code = int(exc.code)
        headers = dict(exc.headers.items()) if exc.headers else {}
        error = str(exc)
    except Exception as exc:  # network evidence must be returned, not raised
        return {
            "status": "failed",
            "status_code": None,
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "size_bytes": 0,
            "headers": {},
            "body": b"",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
    return {
        "status": "ok",
        "status_code": status_code,
        "duration_ms": int((time.perf_counter() - started) * 1000),
        "size_bytes": len(body),
        "headers": headers,
        "body": body,
        "error": error,
    }


def _inspect_html(raw: bytes) -> dict[str, Any]:
    text = raw.decode("utf-8", errors="replace")
    parser = _HtmlInspector()
    parse_error = None
    try:
        parser.feed(text)
    except Exception as exc:
        parse_error = f"{type(exc).__name__}: {exc}"
    lowered = text.lower()
    return {
        "title": parser.title,
        "tag_count": parser.tags,
        "links": parser.links,
        "resources": parser.resources,
        "forms": parser.forms,
        "has_doctype": "<!doctype html" in lowered,
        "has_html_open": "<html" in lowered,
        "has_html_close": "</html>" in lowered,
        "has_body": "<body" in lowered,
        "empty_page": len(re.sub(r"\s+", "", text)) < 80,
        "parse_error": parse_error,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _normalize_internal_path(value: str, base_url: str) -> str | None:
    value = html_lib.unescape(str(value or "").strip())
    if not value or value.startswith(("#", "mailto:", "javascript:", "data:", "tel:")):
        return None
    absolute = urllib.parse.urljoin(base_url.rstrip("/") + "/", value)
    parsed_base = urllib.parse.urlparse(base_url)
    parsed = urllib.parse.urlparse(absolute)
    if (parsed.hostname or "").lower() != (parsed_base.hostname or "").lower() or parsed.port != parsed_base.port:
        return None
    return parsed.path or "/"


def discover_http_report_routes(root: Path = ROOT) -> list[str]:
    source = root / "server" / "api" / "http_server.py"
    if not source.is_file():
        return []
    tree = ast.parse(source.read_text(encoding="utf-8-sig", errors="replace"))
    values: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or not isinstance(node.left, ast.Name) or node.left.id != "path":
            continue
        for comparator in node.comparators:
            if isinstance(comparator, ast.Constant) and isinstance(comparator.value, str) and comparator.value.endswith(".html"):
                values.add(comparator.value)
    return sorted(values)


def discover_renderers(root: Path = ROOT) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for source in sorted((root / "server" / "app").glob("*.py")):
        try:
            text = source.read_text(encoding="utf-8-sig", errors="replace")
            tree = ast.parse(text)
        except Exception:
            continue
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not node.name.startswith("render_"):
                continue
            segment = ast.get_source_segment(text, node) or ""
            if "<html" not in segment.lower() and "<!doctype html" not in segment.lower():
                continue
            result.append({"module": source.relative_to(root).as_posix(), "function": node.name})
    return result


def discover_html_files(root: Path = ROOT) -> list[dict[str, Any]]:
    roots = [root / "web", root / "docs", root / "data" / "reports"]
    result: list[dict[str, Any]] = []
    for base in roots:
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.html")):
            try:
                rel = path.relative_to(root).as_posix()
                started = time.perf_counter()
                raw = path.read_bytes()
                inspected = _inspect_html(raw)
                read_ms = int((time.perf_counter() - started) * 1000)
                result.append({
                    "path": rel,
                    "size_bytes": len(raw),
                    "read_duration_ms": read_ms,
                    "modified_at_epoch": path.stat().st_mtime,
                    "title": inspected["title"],
                    "sha256": inspected["sha256"],
                    "source_kind": "runtime_report" if rel.startswith("data/reports/") else "source_html",
                })
            except OSError as exc:
                result.append({"path": str(path), "status": "failed", "error": str(exc)})
    return result


def _fetch_dynamic_report_inventory(base_url: str, timeout_seconds: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    response = _read_url(base_url.rstrip("/") + "/api/reports", timeout_seconds)
    if response.get("status") != "ok" or response.get("status_code") != 200:
        return [], {k: v for k, v in response.items() if k != "body"}
    try:
        payload = json.loads(response["body"].decode("utf-8", errors="replace"))
        items = payload.get("items") or []
        return [dict(item) for item in items if isinstance(item, dict)], {
            "status": "ok",
            "status_code": 200,
            "duration_ms": response.get("duration_ms"),
            "items_count": len(items),
        }
    except Exception as exc:
        return [], {"status": "failed", "error_type": type(exc).__name__, "error": str(exc)}


def _dynamic_specs(items: Iterable[dict[str, Any]], registered_paths: set[str]) -> list[HtmlPageSpec]:
    result: list[HtmlPageSpec] = []
    for item in items:
        url = str(item.get("url") or "").strip()
        parsed = urllib.parse.urlparse(url)
        if not url or parsed.path in registered_paths or not parsed.path.endswith(".html"):
            continue
        name = str(item.get("name") or Path(parsed.path).name)
        result.append(HtmlPageSpec(
            page_id="runtime_" + re.sub(r"[^a-zA-Z0-9_]+", "_", name).strip("_").lower(),
            url=url,
            title=str(item.get("title") or name),
            category="runtime_report",
            lifecycle="runtime_generated",
            notes="Обнаружено через /api/reports.",
        ))
    return result


def _browser_audit(base_url: str, pages: list[dict[str, Any]], mode: str, timeout_seconds: int) -> dict[str, Any]:
    if mode == "off":
        return {"status": "skipped", "reason": "browser_mode_off", "available": False, "pages": []}
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except Exception as exc:
        status = "failed" if mode == "required" else "skipped"
        return {"status": status, "reason": "playwright_unavailable", "available": False, "error": str(exc), "pages": []}

    results: list[dict[str, Any]] = []
    started_all = time.perf_counter()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=False)
            for item in pages:
                if item.get("http", {}).get("status_code") != 200:
                    continue
                page = context.new_page()
                console_errors: list[str] = []
                failed_requests: list[str] = []
                page.on("console", lambda message, bucket=console_errors: bucket.append(message.text) if message.type == "error" else None)
                page.on("requestfailed", lambda request, bucket=failed_requests: bucket.append(request.url))
                url = urllib.parse.urljoin(base_url.rstrip("/") + "/", str(item.get("url") or ""))
                started = time.perf_counter()
                try:
                    response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)
                    dom_ms = int((time.perf_counter() - started) * 1000)
                    load_started = time.perf_counter()
                    page.wait_for_load_state("load", timeout=timeout_seconds * 1000)
                    load_ms = dom_ms + int((time.perf_counter() - load_started) * 1000)
                    results.append({
                        "page_id": item.get("page_id"),
                        "url": item.get("url"),
                        "status": "ok" if not console_errors and not failed_requests else "warning",
                        "status_code": response.status if response else None,
                        "dom_content_loaded_ms": dom_ms,
                        "page_load_ms": load_ms,
                        "title": page.title(),
                        "console_errors": console_errors[:20],
                        "failed_requests": failed_requests[:20],
                    })
                except Exception as exc:
                    results.append({
                        "page_id": item.get("page_id"),
                        "url": item.get("url"),
                        "status": "failed",
                        "duration_ms": int((time.perf_counter() - started) * 1000),
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                        "console_errors": console_errors[:20],
                        "failed_requests": failed_requests[:20],
                    })
                finally:
                    page.close()
            context.close()
            browser.close()
    except Exception as exc:
        return {"status": "failed" if mode == "required" else "warning", "available": True, "required": mode == "required", "error_type": type(exc).__name__, "error": str(exc), "pages": results}
    failed = sum(1 for row in results if row.get("status") == "failed")
    warnings = sum(1 for row in results if row.get("status") == "warning")
    return {
        "status": "failed" if failed and mode == "required" else "warning" if failed or warnings else "ok",
        "required": mode == "required",
        "available": True,
        "duration_ms": int((time.perf_counter() - started_all) * 1000),
        "pages_tested": len(results),
        "failed": failed,
        "warnings": warnings,
        "pages": results,
    }


def discover_http_get_routes(root: Path = ROOT) -> list[str]:
    """Discover literal GET paths so HTML links to CSV/JSON are not false positives."""
    source = root / "server" / "api" / "http_server.py"
    if not source.is_file():
        return []
    tree = ast.parse(source.read_text(encoding="utf-8-sig", errors="replace"))
    values: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or not isinstance(node.left, ast.Name) or node.left.id != "path":
            continue
        for comparator in node.comparators:
            if isinstance(comparator, ast.Constant) and isinstance(comparator.value, str) and comparator.value.startswith("/"):
                values.add(comparator.value)
    return sorted(values)


def _is_timeout_response(response: dict[str, Any]) -> bool:
    error_type = str(response.get("error_type") or "").lower()
    error = str(response.get("error") or "").lower()
    return "timeout" in error_type or "timed out" in error or "timeout" in error


def _read_url_with_retry(url: str, timeout_seconds: int, slow_ms: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    first = _read_url(url, timeout_seconds)
    attempts = [{k: v for k, v in first.items() if k != "body"}]
    needs_retry = _is_timeout_response(first) or int(first.get("duration_ms") or 0) > slow_ms
    if not needs_retry:
        return first, attempts
    second = _read_url(url, timeout_seconds)
    attempts.append({k: v for k, v in second.items() if k != "body"})
    if second.get("status") == "ok":
        return second, attempts
    return first, attempts


def _runtime_context(base_url: str, timeout_seconds: int) -> dict[str, Any]:
    response = _read_url(base_url.rstrip("/") + "/api/runtime/status", timeout_seconds)
    body = response.pop("body", b"")
    context: dict[str, Any] = {"http": response, "available": False, "background_load_detected": False}
    if response.get("status") != "ok" or response.get("status_code") != 200:
        return context
    try:
        payload = json.loads(body.decode("utf-8", errors="replace"))
    except Exception as exc:
        context["parse_error"] = f"{type(exc).__name__}: {exc}"
        return context
    scheduler = payload.get("scheduler") or {}
    collection = payload.get("collection") or {}
    active_jobs = payload.get("active_jobs") or payload.get("jobs") or []
    background = bool(
        active_jobs
        or scheduler.get("scheduler_started")
        or scheduler.get("scheduler_enabled")
        or collection.get("collection_enabled")
        or payload.get("collection_in_progress")
    )
    context.update({
        "available": True,
        "status": payload.get("status"),
        "active_backend": payload.get("active_backend"),
        "active_jobs": active_jobs,
        "scheduler": scheduler,
        "collection": collection,
        "background_load_detected": background,
    })
    return context


def run_html_audit(
    *,
    base_url: str = DEFAULT_BASE_URL,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    browser_mode: str = "auto",
    allow_non_loopback: bool = False,
    capture_html_dir: Path | None = None,
    root: Path = ROOT,
) -> dict[str, Any]:
    started_all = time.perf_counter()
    base_url = base_url.rstrip("/")
    if not allow_non_loopback and not _is_loopback_base_url(base_url):
        raise ValueError("HTML audit is limited to loopback by default; use allow_non_loopback only for an explicitly approved target.")

    runtime_context = _runtime_context(base_url, timeout_seconds)
    discovered_routes = discover_http_report_routes(root)
    all_get_routes = discover_http_get_routes(root)
    renderers = discover_renderers(root)
    html_files = discover_html_files(root)
    dynamic_items, dynamic_inventory_status = _fetch_dynamic_report_inventory(base_url, timeout_seconds)
    registered_paths = {urllib.parse.urlparse(spec.url).path for spec in REGISTERED_PAGES}
    specs = list(REGISTERED_PAGES) + _dynamic_specs(dynamic_items, registered_paths)
    known_report_paths = set(discovered_routes)
    known_report_paths.update(str(item.get("url") or "").split("?", 1)[0] for item in dynamic_items)
    known_paths = {"/", *known_report_paths, *all_get_routes}

    pages: list[dict[str, Any]] = []
    captures: list[str] = []
    for spec in specs:
        item: dict[str, Any] = asdict(spec)
        item["expected_status"] = list(spec.expected_status)
        if not spec.safe_get:
            item["status"] = "skipped"
            item["reason"] = "registry_safe_get_false"
            pages.append(item)
            continue

        absolute = urllib.parse.urljoin(base_url + "/", spec.url.lstrip("/"))
        response, attempts = _read_url_with_retry(absolute, timeout_seconds, spec.slow_ms)
        body = response.pop("body", b"")
        item["http"] = response
        item["http_attempts"] = attempts
        item["retried"] = len(attempts) > 1
        item["url_absolute"] = absolute
        if body:
            inspected = _inspect_html(body)
            internal_links = sorted({p for value in inspected["links"] if (p := _normalize_internal_path(value, base_url))})
            internal_resources = sorted({p for value in inspected["resources"] if (p := _normalize_internal_path(value, base_url))})
            broken_internal_links = sorted(path for path in internal_links if path not in known_paths and not path.startswith("/api/"))
            broken_internal_resources = sorted(path for path in internal_resources if path not in known_paths)
            post_forms = [form for form in inspected["forms"] if form.get("method") not in {"", "get"}]
            item["html"] = {
                **{k: v for k, v in inspected.items() if k not in {"links", "resources", "forms"}},
                "internal_links_count": len(internal_links),
                "internal_resources_count": len(internal_resources),
                "broken_internal_links": broken_internal_links,
                "broken_internal_resources": broken_internal_resources,
                "non_get_forms": post_forms,
            }
            if capture_html_dir is not None:
                capture_html_dir.mkdir(parents=True, exist_ok=True)
                capture = capture_html_dir / f"{spec.page_id}.html"
                capture.write_bytes(body)
                captures.append(str(capture))

        status_code = response.get("status_code")
        html_info = item.get("html") or {}
        content_type = str((response.get("headers") or {}).get("Content-Type") or "").lower()
        functional: list[str] = []
        performance: list[str] = []
        timeout_seen = any(_is_timeout_response(attempt) for attempt in attempts)
        slow_seen = any(int(attempt.get("duration_ms") or 0) > spec.slow_ms for attempt in attempts)
        if timeout_seen:
            performance.append("http_timeout")
        if slow_seen:
            performance.append("slow_http_response")
        if len(attempts) > 1 and response.get("status") == "ok":
            performance.append("recovered_on_isolated_retry")

        if response.get("status") == "failed" and not _is_timeout_response(response):
            functional.append("network_error")
        if response.get("status") != "failed" and status_code not in spec.expected_status:
            functional.append(f"unexpected_status:{status_code}")
        if status_code == 200 and "text/html" not in content_type:
            functional.append("unexpected_content_type")
        if status_code == 200 and not html_info.get("has_html_open"):
            functional.append("missing_html_element")
        if html_info.get("empty_page"):
            functional.append("empty_page")
        if html_info.get("parse_error"):
            functional.append("html_parse_error")
        if html_info.get("broken_internal_resources"):
            functional.append("broken_internal_resources")
        if html_info.get("broken_internal_links"):
            functional.append("broken_internal_links")

        critical_functional = {
            "network_error", "unexpected_content_type", "missing_html_element", "empty_page", "html_parse_error"
        }
        is_failed = any(problem in critical_functional or problem.startswith("unexpected_status") for problem in functional)
        item["functional_findings"] = functional
        item["performance_findings"] = performance
        item["problems"] = functional + performance
        item["status"] = "failed" if is_failed else "warning" if functional or performance else "ok"
        pages.append(item)

    browser = _browser_audit(base_url, pages, browser_mode, timeout_seconds)
    browser_by_id = {row.get("page_id"): row for row in browser.get("pages") or []}
    for page in pages:
        if page.get("page_id") in browser_by_id:
            page["browser"] = browser_by_id[page["page_id"]]
            if browser_by_id[page["page_id"]].get("status") == "failed":
                page["status"] = "failed" if browser_mode == "required" else "warning"
                page.setdefault("functional_findings", []).append("browser_failed")
                page.setdefault("problems", []).append("browser_failed")
            elif browser_by_id[page["page_id"]].get("status") == "warning" and page.get("status") == "ok":
                page["status"] = "warning"
                page.setdefault("functional_findings", []).append("browser_warning")
                page.setdefault("problems", []).append("browser_warning")

    raw_hash_groups: dict[str, list[str]] = {}
    title_groups: dict[str, list[str]] = {}
    for page in pages:
        digest = str((page.get("html") or {}).get("sha256") or "")
        title = str((page.get("html") or {}).get("title") or "").strip().lower()
        if digest:
            raw_hash_groups.setdefault(digest, []).append(str(page.get("page_id")))
        if title:
            title_groups.setdefault(title, []).append(str(page.get("page_id")))
    duplicate_bodies = [values for values in raw_hash_groups.values() if len(values) > 1]
    duplicate_titles = [values for values in title_groups.values() if len(values) > 1]

    route_paths = set(discovered_routes)
    registry_paths = {urllib.parse.urlparse(spec.url).path for spec in REGISTERED_PAGES}
    dynamic_paths = {str(item.get("url") or "").split("?", 1)[0] for item in dynamic_items}
    uncovered_routes = sorted(route_paths - registry_paths - dynamic_paths)
    advertised_without_explicit_route = sorted(path for path in dynamic_paths if path not in route_paths and path not in {row.get("url", "").split("?", 1)[0] for row in dynamic_items if not row.get("dynamic")})

    failed = [page for page in pages if page.get("status") == "failed"]
    warnings = [page for page in pages if page.get("status") == "warning"]
    skipped = [page for page in pages if page.get("status") == "skipped"]
    performance_pages = [page for page in pages if page.get("performance_findings")]
    functional_warning_pages = [page for page in warnings if page.get("functional_findings")]
    slowest = sorted(
        ({
            "page_id": page.get("page_id"),
            "url": page.get("url"),
            "http_duration_ms": (page.get("http") or {}).get("duration_ms"),
            "browser_load_ms": (page.get("browser") or {}).get("page_load_ms"),
            "retried": page.get("retried"),
        } for page in pages if (page.get("http") or {}).get("duration_ms") is not None),
        key=lambda row: int(row.get("browser_load_ms") or row.get("http_duration_ms") or 0),
        reverse=True,
    )[:10]
    lifecycle_review = [
        {"page_id": page.get("page_id"), "url": page.get("url"), "lifecycle": page.get("lifecycle"), "status": page.get("status")}
        for page in pages if page.get("lifecycle") != "active"
    ]
    overall = "failed" if failed or browser.get("status") == "failed" else "warning" if warnings or uncovered_routes or duplicate_bodies or browser.get("status") == "skipped" else "ok"
    return {
        "package_type": "HTML_AUDIT_2",
        "status": overall,
        "generated_at_utc": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "duration_ms": int((time.perf_counter() - started_all) * 1000),
        "safety": {
            "base_url": base_url,
            "loopback_only": not allow_non_loopback,
            "method": "GET only",
            "state_changing_routes_invoked": False,
            "html_capture_enabled": capture_html_dir is not None,
            "isolated_retry_policy": "one retry for timeout or slow response",
        },
        "runtime_context": runtime_context,
        "summary": {
            "pages_registered": len(REGISTERED_PAGES),
            "runtime_pages_discovered": len(dynamic_items),
            "pages_tested": len(pages) - len(skipped),
            "pages_ok": sum(1 for page in pages if page.get("status") == "ok"),
            "pages_warning": len(warnings),
            "pages_failed": len(failed),
            "pages_skipped": len(skipped),
            "functional_failures": len(failed),
            "functional_warnings": len(functional_warning_pages),
            "performance_findings": len(performance_pages),
            "renderers_discovered": len(renderers),
            "source_html_files": len(html_files),
        },
        "inventory": {
            "registered_pages": [asdict(spec) | {"expected_status": list(spec.expected_status)} for spec in REGISTERED_PAGES],
            "http_report_routes": discovered_routes,
            "http_get_routes": all_get_routes,
            "runtime_reports_status": dynamic_inventory_status,
            "runtime_reports": dynamic_items,
            "renderers": renderers,
            "html_files": html_files,
            "uncovered_http_routes": uncovered_routes,
            "advertised_without_explicit_route": advertised_without_explicit_route,
        },
        "analysis": {
            "slowest_pages": slowest,
            "functional_failures": [{"page_id": page.get("page_id"), "url": page.get("url"), "findings": page.get("functional_findings")} for page in failed],
            "functional_warnings": [{"page_id": page.get("page_id"), "url": page.get("url"), "findings": page.get("functional_findings")} for page in functional_warning_pages],
            "performance_findings": [{"page_id": page.get("page_id"), "url": page.get("url"), "findings": page.get("performance_findings"), "attempts": page.get("http_attempts")} for page in performance_pages],
            "failed_pages": [{"page_id": page.get("page_id"), "url": page.get("url"), "problems": page.get("problems")} for page in failed],
            "warning_pages": [{"page_id": page.get("page_id"), "url": page.get("url"), "problems": page.get("problems")} for page in warnings],
            "duplicate_body_candidates": duplicate_bodies,
            "duplicate_title_candidates": duplicate_titles,
            "lifecycle_review": lifecycle_review,
            "captures": captures,
        },
        "browser": {k: v for k, v in browser.items() if k != "pages"},
        "pages": pages,
    }
