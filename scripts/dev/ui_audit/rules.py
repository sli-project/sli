#!/usr/bin/env python3
"""SLI UI auditor, step 2: deterministic checks over crawl evidence.

Usage::

    python scripts/dev/ui_audit/rules.py RUN_DIR/ru/evidence.jsonl [RUN_DIR/en/evidence.jsonl ...] \
        [--out RUN_DIR]

Writes ``findings.json`` and ``findings.md`` into --out (default: the parent of
the first evidence directory). Evidence pointers are ``source/id`` plus the
screenshot path relative to the run directory.

Checks (finding ``type``):
  api_error            4xx/5xx API response
  console_error        console error / uncaught exception
  failed_request       request that failed at network level
  slow_settle          stabilization measurement, not an established regression
  route_404            navigation answered 4xx/5xx or the page says "not found"
  placeholder_data     empty state / empty table shown while an API call in the same
                       state returned rows, or the entity overview shows items on the
                       topic of the empty tab
  static_stub          the same placeholder text repeated across >= 3 states
  untranslated_en      Cyrillic UI text in English mode (server data/names excluded)
  metric_mismatch      metric and table totals disagree for the same population
  computer_partition_mismatch  disjoint computer categories do not sum to all
  crawler_error        the crawler itself failed on a state

With ``--batches DIR`` the evidence is also split into self-contained review
batches (<= 20 pages each: digest, rule findings, screenshots, review prompt) for
run_review.sh.

This is a dev tool; it does not touch runtime code or any database.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

SLOW_MS = 8000
STUB_MIN_CONTEXTS = 3
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

NOT_FOUND = re.compile(r"(страница не найдена|не найдено\b.*страниц|404|page not found|not found)", re.IGNORECASE)
EMPTY_TITLE = re.compile(r"^(нет\b|ничего|пуст|no\b|nothing|empty|не найден|not found)", re.IGNORECASE)
GENERIC_EMPTY = re.compile(r"(ничего не найдено|по выбранным условиям записей нет|nothing found|no records match)", re.IGNORECASE)


def load(paths: list[Path]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in paths:
        source = path.parent.name
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            rec["_source"] = source
            rec["_line"] = line_no
            records.append(rec)
    return records


def shot(rec: dict[str, Any]) -> str:
    s = rec.get("screenshot")
    return f"{rec['_source']}/{s}" if s else ""


def path_of(url: str) -> str:
    return url.split("?", 1)[0]


def route_template(url: str) -> str:
    return re.sub(r"/(?:\d+|[0-9a-f-]{16,})(?=/|$)", "/:id", urlsplit(url).path, flags=re.IGNORECASE)


class Findings:
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []
        self._seen: dict[tuple, dict[str, Any]] = {}

    def add(self, ftype: str, severity: str, rec: dict[str, Any], message: str, dedupe: tuple | None = None, **extra: Any) -> None:
        locale = rec.get("locale") if ftype == "untranslated_en" else None
        key = (ftype, locale, dedupe if dedupe is not None else (rec.get("url"), rec.get("state"), message))
        if key in self._seen:
            prev = self._seen[key]
            prev["count"] = prev.get("count", 1) + 1
            if len(prev.setdefault("also_pages", [])) < 8 and rec.get("url") != prev["page"]:
                prev["also_pages"].append(rec.get("url"))
            return
        item = {
            "type": ftype, "severity": severity, "locale": rec.get("locale"), "page": rec.get("url"),
            "state": rec.get("state"), "message": message,
            "evidence": {"source": rec["_source"], "id": rec.get("id"), "line": rec["_line"], "screenshot": shot(rec)},
            **extra,
        }
        self._seen[key] = item
        self.items.append(item)


def check_api(recs, out: Findings) -> None:
    for rec in recs:
        for call in rec.get("api_calls") or []:
            status = call.get("status") or 0
            if status >= 400:
                sev = "high" if status >= 500 else ("low" if status in (401, 403) else "medium")
                out.add("api_error", sev, rec, f"{call['method']} {path_of(call['url'])} -> HTTP {status}", dedupe=(rec.get("url"), call["method"], path_of(call["url"]), status))


def check_console(recs, out: Findings) -> None:
    for rec in recs:
        for err in rec.get("console_errors") or []:
            message = err.get("text", "") if isinstance(err, dict) else err
            resource = message.startswith("Failed to load resource")
            if resource:
                status = re.search(r"\b(\d{3})\b", message)
                location = err.get("url") if isinstance(err, dict) else None
                matches = [c for c in rec.get("api_calls") or [] if (c.get("status") or 0) >= 400
                           and (not status or c["status"] == int(status[1]))
                           and (not location or urlsplit(c["url"]).path == urlsplit(location).path)]
                # Old evidence has no console location: only an unambiguous match is usable.
                if len({(c.get("method"), path_of(c["url"]), c["status"]) for c in matches}) == 1:
                    call = matches[0]
                    dedupe = (rec.get("url"), call["method"], path_of(call["url"]), call["status"])
                    key = ("api_error", None, dedupe)
                    if key not in out._seen:
                        out.add("api_error", "high" if call["status"] >= 500 else ("low" if call["status"] in (401, 403) else "medium"),
                                rec, f"{call['method']} {path_of(call['url'])} -> HTTP {call['status']}", dedupe=dedupe)
                    linked = out._seen[key]
                    linked.setdefault("console_messages", [])
                    if message[:240] not in linked["console_messages"]:
                        linked["console_messages"].append(message[:240])
                    continue
            out.add("console_error", "low" if resource else "medium", rec, message[:240], dedupe=(rec.get("url"), message[:120]))
        for fr in rec.get("failed_requests") or []:
            if "ERR_ABORTED" in fr.get("error", ""):
                continue
            transient = any(x in fr.get("error", "") for x in ("ERR_CONNECTION_REFUSED", "ERR_CONNECTION_RESET", "ERR_EMPTY_RESPONSE"))
            note = " (вероятно, перегрузка сервера во время обхода; перепроверьте)" if transient else ""
            out.add("failed_request", "low" if transient else "medium", rec, f"{fr['method']} {fr['url']}: {fr['error']}{note}", dedupe=(rec.get("url"), fr["url"], fr["error"]))


def check_timing(recs, out: Findings) -> None:
    for rec in recs:
        if rec.get("action") is None and rec.get("state") != "page":
            continue
        ms = rec.get("settle_ms") or 0
        if rec.get("settle_timeout") or rec.get("still_busy"):
            out.add("slow_settle", "medium", rec, f"Измерение: загрузка не завершилась за {ms} мс в этом проходе; причина и регрессия не установлены",
                    classification="measurement", settle_ms=ms, completed=False)
        elif ms > SLOW_MS:
            out.add("slow_settle", "info", rec, f"Измерение: стабилизация заняла {ms} мс (> {SLOW_MS}); для вывода о регрессии нужны длительности запросов и повторное измерение",
                    classification="measurement", settle_ms=ms, completed=True)


def check_404(recs, out: Findings) -> None:
    for rec in recs:
        status = rec.get("nav_status")
        headings = " ".join(rec.get("headings") or [])
        if (isinstance(status, int) and status >= 400) or (rec.get("state") == "page" and NOT_FOUND.search(headings) and (rec.get("text_len") or 0) < 1200):
            out.add("route_404", "high", rec, f"Маршрут отдаёт ошибку (HTTP {status}) или страницу «не найдено»; найден по ссылке со страницы {rec.get('from')}")


def report_key(rec) -> str | None:
    match = re.fullmatch(r"/app/report/([^/]+)", urlsplit(rec.get("url") or "").path)
    return match[1] if match else None


def query_params(url: str) -> dict[str, str]:
    return {k: v[-1] for k, v in parse_qs(urlsplit(url).query).items()}


def active_collection(rec) -> str:
    if rec.get("active_collection"):
        return rec["active_collection"]
    params = query_params(rec.get("url") or "")
    tab = params.get("tab")
    return f"collections.{tab}" if tab and tab != "table" else "items"


def collection_calls(rec) -> list[tuple[dict[str, Any], str, int]]:
    """Select the displayed report collection, never a payload-wide row maximum."""
    key = report_key(rec)
    if not key:
        return []
    collection = active_collection(rec)
    expected = f"/api/v2/reports/{key}/data"
    result = []
    for call in rec.get("api_calls") or []:
        if call.get("status") != 200 or urlsplit(call.get("url", "")).path != expected:
            continue
        # Ignore responses belonging to a previously selected population.
        page_params = query_params(rec.get("url") or "")
        call_params = query_params(call["url"])
        if any(call_params.get(k) != v for k, v in page_params.items() if k not in {"tz", "limit", "cursor", "sort", "direction"}):
            continue
        count = (call.get("arrays") or {}).get(collection)
        if isinstance(count, int):
            result.append((call, collection, count))
    return result


def check_placeholder_data(recs, out: Findings) -> None:
    parents = {}
    for rec in recs:
        if rec.get("state") == "page":
            parents[(rec["_source"], rec["url"])] = rec
    for rec in recs:
        empties = [p for p in rec.get("placeholders") or [] if (p.get("state") == "empty" or EMPTY_TITLE.search(p.get("title", ""))) and p.get("role") != "alert"]
        empty_tables = [t for t in rec.get("tables") or [] if t.get("rows") == 0 and not t.get("in_dialog")]
        if not empties and not empty_tables:
            continue
        rows = [(c, path, count) for c, path, count in collection_calls(rec) if count > 0]
        shows_rows = any(t.get("rows", 0) > 0 and not t.get("in_dialog") for t in rec.get("tables") or [])
        if rows and not shows_rows and not rec.get("dialog_open"):
            top, collection, count = rows[-1]
            what = empties[0]["title"] if empties else "пустая таблица"
            out.add("placeholder_data", "medium", rec, f"Показан placeholder «{what}», но API {path_of(top['url'])} в отображаемой коллекции {collection} вернул строк: {count}", dedupe=(rec.get("url"), rec.get("state")))
            continue
        # tab vs overview of the same entity
        if rec.get("action") in ("tab", "dialog-tab") and empties:
            parent = parents.get((rec["_source"], rec.get("parent_url")))
            if not parent:
                continue
            # A heading, entity name or profile is not evidence of a relationship.
            # Require structured, authorized records from the exact tab source/direction.
            tab = rec.get("tab_source") or {}
            required = ("url", "collection", "relation_kind", "direction", "entity_id")
            if not all(tab.get(k) for k in required) or tab.get("authorized") is not True:
                continue
            for relation in parent.get("relation_evidence") or []:
                if (all(relation.get(k) == tab[k] for k in required)
                        and relation.get("authorized") is True and relation.get("rows", 0) > 0):
                    out.add("placeholder_data", "high", rec,
                            f"Вкладка «{rec.get('tab_label')}» пуста, но тот же разрешённый источник связи {tab['collection']} показывает записей: {relation['rows']}",
                            dedupe=(rec.get("url"), tuple(tab[k] for k in required)))
                    break


def check_static_stub(recs, out: Findings) -> None:
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for rec in recs:
        for p in rec.get("placeholders") or []:
            if not (p.get("state") == "empty" or EMPTY_TITLE.search(p.get("title", ""))) or p.get("role") == "alert":
                continue  # banners (partial/stale/unavailable) and "how to read" notes are not stubs
            # Older crawls did not capture detail; an empty text is not proof of a stub.
            if "detail" not in p and not p.get("text"):
                continue
            explanation = " ".join(filter(None, (p.get("text", ""), p.get("detail", ""))))
            groups[(rec["_source"], p.get("title", ""), explanation)].append(rec)
    for (source, title, text), items in groups.items():
        contexts = set()
        for rec in items:
            # The clicked control may be a population filter, not the displayed tab.
            tab = query_params(rec["url"]).get("tab")
            selected = tuple(t["label"] for t in rec.get("tabs") or [] if t.get("selected"))
            context = tab or selected or rec.get("tab_label") or rec.get("state")
            contexts.add((source, route_template(rec["url"]), context))
        if len(contexts) < STUB_MIN_CONTEXTS:
            continue
        generic = bool(GENERIC_EMPTY.search(title + " " + text)) or title.lower() in ("нет строк", "no rows")
        sample = items[0]
        out.add("static_stub", "low" if generic else "medium", sample,
                f"Один и тот же placeholder «{title}: {text[:120]}» встречается в {len(contexts)} разных состояниях ({', '.join(sorted({r['url'] + ' [' + str(r.get('state')) + ']' for r in items})[:5])})",
                dedupe=(source, title, text), count=len(contexts))


def check_cyrillic(recs, out: Findings) -> None:
    """One finding per page (query/ids folded): all Cyrillic UI strings seen on it in en mode."""
    by_page: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for rec in recs:
        if rec.get("locale") != "en":
            continue
        page = re.sub(r"/\d+", "/:id", path_of(rec.get("url") or ""))
        for item in rec.get("cyrillic") or []:
            text = item.get("template", item["text"])
            if item.get("origin") == "data" and "template" not in item:
                continue
            if not re.search(r"[А-Яа-яЁё]", text):
                continue
            by_page[page].setdefault(text, rec)
    for page, strings in by_page.items():
        first = next(iter(strings.values()))
        sample = "; ".join(f"«{t[:70]}»" for t in list(strings)[:10])
        out.add("untranslated_en", "medium", first, f"Русский текст в английском интерфейсе ({len(strings)} строк): {sample}", dedupe=(page,), count=len(strings), strings=list(strings)[:60])


def to_int(value: str) -> int | None:
    m = re.fullmatch(r"\s*[-+]?[\d\s .,]+\s*", value or "")
    if not m:
        return None
    digits = re.sub(r"[^\d]", "", value)
    return int(digits) if digits else None


# Exact legacy labels support old evidence; new crawls retain API metric keys.
METRIC_LABELS = {
    "ad.computers.v6": {
        "all": ("Всего в AD", "Total in AD"), "attention": ("Требуют внимания", "Require attention", "Need attention"),
        "ws": ("Рабочие станции (вкл.)", "Workstations (enabled)"), "srv": ("Серверы (вкл.)", "Servers (enabled)"),
        "unknown": ("Тип не определён (вкл.)", "Unknown type (enabled)"),
        "disabled": ("Отключены (все типы)", "Disabled (all types)"),
        "unknown_state": ("Состояние учётной записи не определено", "Account state unknown"),
    },
    "vpn.accounts": {"total_users": ("Всего VPN-пользователей", "Total VPN users")},
}
METRIC_POPULATIONS = {
    "ad.computers.v6": {
        "all": {"view": "all"}, "attention": {"view": "attention"},
        "ws": {"view": "workstation_enabled"}, "srv": {"view": "server_enabled"},
        "unknown": {"view": "all", "type": "unknown", "enabled": "enabled"},
        "disabled": {"view": "all", "enabled": "disabled"},
        "unknown_state": {"view": "all", "enabled": "unknown"},
    },
    "vpn.accounts": {"total_users": {}},
}
TRANSPORT_PARAMS = {"tz", "limit", "cursor", "sort", "sort_by", "direction", "sort_direction", "threshold_days", "tab"}


def keyed_metrics(rec) -> dict[str, dict[str, Any]]:
    key = report_key(rec)
    labels = METRIC_LABELS.get(key, {})
    result = {}
    for metric in rec.get("metrics") or []:
        if metric.get("in_dialog"):
            continue
        metric_key = metric.get("key")
        if not metric_key:
            metric_key = next((k for k, values in labels.items() if metric.get("label") in values), None)
        if metric_key and to_int(str(metric.get("value", ""))) is not None:
            result[metric_key] = metric
    return result


def check_metric_table(recs, out: Findings) -> None:
    for rec in recs:
        tables = [t for t in rec.get("tables") or [] if not t.get("in_dialog") and isinstance(t.get("total"), int)]
        metrics = keyed_metrics(rec)
        key = report_key(rec)
        calls = collection_calls(rec)
        if not tables or not metrics or not calls:
            continue
        call, collection, _ = calls[-1]
        if collection != "items":
            continue
        population = {k: v for k, v in query_params(call["url"]).items() if k not in TRANSPORT_PARAMS}
        if key == "ad.computers.v6":
            population.setdefault("view", "attention")
        for metric_key, metric in metrics.items():
            if metric.get("source_url") and metric["source_url"] != call["url"]:
                continue
            expected = METRIC_POPULATIONS.get(key, {}).get(metric_key)
            if expected is None or population != expected:
                continue
            for table in tables:
                if table.get("collection", "items") != collection:
                    continue
                if table.get("source_url"):
                    if table["source_url"] != call["url"]:
                        continue
                elif len(tables) != 1:
                    continue
                if to_int(str(metric["value"])) != table["total"]:
                    out.add("metric_mismatch", "medium", rec,
                            f"Метрика «{metric['label']}» = {metric['value']}, а таблица той же выборки {collection} показывает «{table.get('footer')}» (итого {table['total']})",
                            dedupe=(rec.get("url"), metric_key, table["total"]), metric_key=metric_key, collection=collection, population=population)


def check_computer_partition(recs, out: Findings) -> None:
    parts = ("ws", "srv", "unknown", "disabled", "unknown_state")
    for rec in recs:
        if report_key(rec) != "ad.computers.v6":
            continue
        metrics = keyed_metrics(rec)
        if not all(key in metrics for key in (*parts, "all")):
            continue  # Missing/unavailable categories are not zero.
        values = {key: to_int(str(metrics[key]["value"])) for key in (*parts, "all")}
        total = sum(values[key] for key in parts)
        if total != values["all"]:
            out.add("computer_partition_mismatch", "medium", rec,
                    f"Разбиение компьютеров ws + srv + unknown + disabled + unknown_state = {total}, но all = {values['all']}",
                    dedupe=(rec["_source"], tuple(values.items())), metrics=values)


def check_crawler(recs, out: Findings) -> None:
    for rec in recs:
        if rec.get("state") == "crawler-error" or rec.get("error"):
            out.add("crawler_error", "low", rec, f"Сбой при обходе: {rec.get('error')}")


def run(paths: list[Path], out_dir: Path) -> dict[str, Any]:
    recs = load(paths)
    out = Findings()
    for check in (check_api, check_console, check_timing, check_404, check_placeholder_data, check_static_stub, check_cyrillic, check_metric_table, check_computer_partition, check_crawler):
        check(recs, out)
    items = sorted(out.items, key=lambda f: (SEVERITY_ORDER[f["severity"]], f["type"], f["page"] or ""))
    for i, f in enumerate(items, 1):
        f["id"] = f"F{i:03d}"
    by_type: dict[str, int] = defaultdict(int)
    by_sev: dict[str, int] = defaultdict(int)
    for f in items:
        by_type[f["type"]] += 1
        by_sev[f["severity"]] += 1
    summary = {
        "states": len(recs), "pages": len({(r["_source"], path_of(r["url"])) for r in recs if r.get("url")}),
        "findings": len(items), "by_type": dict(by_type), "by_severity": dict(by_sev),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "findings.json").write_text(json.dumps({"summary": summary, "findings": items}, ensure_ascii=False, indent=1), encoding="utf-8")
    lines = ["# Находки детерминированных правил", "", f"Состояний: {summary['states']}, страниц: {summary['pages']}, находок: {summary['findings']}", "",
             "| Тип | Кол-во |", "|---|---|"] + [f"| {k} | {v} |" for k, v in sorted(by_type.items())] + ["", "| Серьёзность | Кол-во |", "|---|---|"] + [f"| {k} | {by_sev[k]} |" for k in SEVERITY_ORDER if k in by_sev] + [""]
    current = None
    for f in items:
        if f["severity"] != current:
            current = f["severity"]
            lines += [f"## {current}", ""]
        ev = f["evidence"]
        lines.append(f"- **{f['id']}** `{f['type']}` [{f['locale']}] `{f['page']}` ({f['state']}): {f['message']}  \n  evidence: `{ev['source']}/{ev['id']}` (строка {ev['line']}), скриншот: `{ev['screenshot']}`")
    (out_dir / "findings.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary


def digest(rec: dict[str, Any]) -> str:
    """Compact human-readable evidence for one state (what the LLM reviewer reads)."""
    calls = rec.get("api_calls") or []
    lines = [f"### {rec['_source']}/{rec.get('id')} state=`{rec.get('state')}` url=`{rec.get('url')}`",
             f"- settle: {rec.get('settle_ms')} мс; скриншот: `shots/{Path(rec.get('screenshot') or '').name}`",
             f"- заголовки: {'; '.join(rec.get('headings') or [])[:300]}"]
    if rec.get("tabs"):
        lines.append("- вкладки: " + ", ".join(("*" if t.get("selected") else "") + t["label"] for t in rec["tabs"]))
    for t in rec.get("tables") or []:
        lines.append(f"- таблица «{t.get('caption')}»: строк {t.get('rows')}, подвал «{t.get('footer')}», колонки: {', '.join(t.get('headers') or [])[:200]}")
    for m in rec.get("metrics") or []:
        lines.append(f"- метрика «{m.get('label')}» = {m.get('value')} {m.get('caption', '')}".rstrip())
    for p in rec.get("placeholders") or []:
        lines.append(f"- placeholder [{p.get('state') or p.get('tone')}]: «{p.get('title')}» {p.get('text', '')} {p.get('detail', '')}")
    for c in calls:
        lines.append(f"- API {c.get('method')} {path_of(c.get('url', ''))} -> {c.get('status')} rows={c.get('rows')} total={c.get('total')}")
    for e in rec.get("console_errors") or []:
        message = e.get("text", "") if isinstance(e, dict) else e
        lines.append(f"- console: {message[:160]}")
    text = (rec.get("dialog_text") or rec.get("text") or "").replace("\n", " | ")
    lines.append(f"- текст: {text[:1500]}")
    return "\n".join(lines)


def make_batches(paths: list[Path], findings_path: Path, dest: Path, size: int) -> int:
    """Split evidence into batches of <= size pages; each batch folder is self-contained."""
    import shutil

    recs = load(paths)
    findings = json.loads(findings_path.read_text(encoding="utf-8"))["findings"] if findings_path.exists() else []
    pages: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for rec in recs:
        key = (rec.get("locale", ""), rec.get("parent_url") or rec.get("url") or "")
        pages.setdefault(key, []).append(rec)
    keys = sorted(pages)
    dest.mkdir(parents=True, exist_ok=True)
    here = Path(__file__).resolve().parent
    count = 0
    for start in range(0, len(keys), size):
        count += 1
        chunk = keys[start:start + size]
        folder = dest / f"batch_{count:02d}"
        (folder / "shots").mkdir(parents=True, exist_ok=True)
        shutil.copy(here / "review_prompt.md", folder / "review_prompt.md")
        body = [f"# Пакет {count}: страниц {len(chunk)}", ""]
        for key in chunk:
            body.append(f"## [{key[0]}] {key[1]}")
            for rec in pages[key]:
                body.append(digest(rec))
                src = next((p.parent for p in paths if p.parent.name == rec["_source"]), None)
                if src and rec.get("screenshot") and (src / rec["screenshot"]).exists():
                    shutil.copy(src / rec["screenshot"], folder / "shots" / Path(rec["screenshot"]).name)
            body.append("")
        (folder / "evidence_digest.md").write_text("\n".join(body), encoding="utf-8")
        urls = {k[1] for k in chunk}
        mine = [f for f in findings if f["page"] in urls or path_of(f["page"] or "") in urls]
        lines = ["# Находки правил для этого пакета", ""] + [f"- {f['id']} [{f['severity']}] `{f['type']}` `{f['page']}`: {f['message']}" for f in mine]
        (folder / "findings_batch.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description="Детерминированные проверки evidence.jsonl аудитора UI.")
    parser.add_argument("evidence", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--batches", type=Path, default=None, help="после проверок разложить evidence по пакетам для LLM-ревью в эту папку")
    parser.add_argument("--batch-size", type=int, default=20)
    args = parser.parse_args()
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # Windows consoles default to cp1251/cp866
        except (AttributeError, ValueError):
            pass
    out_dir = args.out or args.evidence[0].resolve().parent.parent
    paths = [p.resolve() for p in args.evidence]
    summary = run(paths, out_dir)
    print(json.dumps(summary, ensure_ascii=False))
    if args.batches:
        n = make_batches(paths, out_dir / "findings.json", args.batches.resolve(), max(1, min(args.batch_size, 20)))
        print(f"batches: {n} -> {args.batches}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
