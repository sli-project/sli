"""Report declarations and request-parameter parsing (ADR 0010)."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, fields
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from typing import Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from server.sli.access.scope import AccessScope
from server.sli.core.messages import message
from server.sli.reporting.report_intent_contract import (
    ALLOWED_ARCHETYPES,
    REQUIRED_ACCEPTANCE_LANES,
    REQUIRED_HONEST_STATES,
)

ParamKind = Literal["text", "choice", "multichoice", "period", "int", "domain"]
ColumnKind = Literal["text", "number", "datetime", "date", "boolean", "code", "list", "state"]


class ResultState(str, Enum):
    """Wire states shared by all v2 reports; absence of rows is not coverage."""

    OK = "ok"
    EMPTY = "empty"
    DENIED = "denied"
    NOT_COLLECTED = "not_collected"
    PARTIAL = "partial"
    PROCESSING = "processing"
    STALE = "stale"
    ERROR = "error"


def source_state(value: Any) -> str:
    """Translate reader vocabulary at the adapter boundary, failing visibly."""
    aliases = {
        "available": "ok", "not_authorized": "denied", "unavailable": "error", "failed": "error",
        "empty_unverified": "partial", "coverage_unverified": "partial", "identity_incomplete": "partial",
    }
    try:
        return ResultState(aliases.get(value, value)).value
    except (ValueError, TypeError):
        return ResultState.ERROR.value


PERIOD_PRESETS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30), "90d": timedelta(days=90)}
# Keys every report understands; they are not declared per report.
RESERVED_KEYS = frozenset({"cursor", "limit", "sort", "direction", "tz", "tab"})
TEXT_MAX = 256


@dataclass(frozen=True)
class Param:
    key: str
    label: str
    kind: ParamKind
    options: tuple[tuple[str, str], ...] = ()
    #: Name of a ``filter_options`` entry the report fills at query time.
    options_from: str | None = None
    default: Any = None
    required: bool = False
    max_days: int | None = None
    presets: tuple[str, ...] = ("24h", "7d", "30d", "90d", "custom")
    #: Kept in the URL and sent to the query, but not shown in the filter bar (deep links).
    hidden: bool = False
    #: Extra categories beyond the report core; checked atomically with it.
    field_categories: frozenset[str] = frozenset()
    max_length: int = TEXT_MAX

    @classmethod
    def text(cls, key: str, label: str, *, max_length: int = TEXT_MAX) -> Param:
        if not 1 <= max_length <= 4096:
            raise ValueError("report_parameter_length_invalid")
        return cls(key, label, "text", max_length=max_length)

    @classmethod
    def choice(cls, key: str, label: str, options: Sequence[tuple[str, str]] = (), *, default: str | None = None, options_from: str | None = None) -> Param:
        return cls(key, label, "choice", tuple(options), options_from, default)

    @classmethod
    def integer(cls, key: str, label: str, *, hidden: bool = False) -> Param:
        return cls(key, label, "int", hidden=hidden)

    @classmethod
    def period(cls, *, default: str = "7d", max_days: int | None = None, presets: Sequence[str] = ("24h", "7d", "30d", "90d", "custom")) -> Param:
        return cls("period", "Период", "period", default=default, required=True, max_days=max_days, presets=tuple(presets))

    @classmethod
    def domain(cls, *, options_from: str = "domain") -> Param:
        return cls("domain", "Домен", "domain", options_from=options_from, required=True)

    def to_json(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"key": self.key, "label": self.label, "kind": self.kind}
        if self.options:
            payload["options"] = [{"value": value, "label": label} for value, label in self.options]
        if self.options_from:
            payload["options_from"] = self.options_from
        if self.default is not None:
            payload["default"] = self.default
        if self.required:
            payload["required"] = True
        if self.hidden:
            payload["hidden"] = True
        if self.kind == "text" and self.max_length != TEXT_MAX:
            payload["max_length"] = self.max_length
        if self.kind == "period":
            payload["presets"] = list(self.presets)
            if self.max_days:
                payload["max_days"] = self.max_days
        return payload


@dataclass(frozen=True)
class Column:
    key: str
    label: str
    kind: ColumnKind = "text"
    #: Dot path into the row; defaults to ``key``.
    path: str | None = None
    sortable: bool = False
    #: ``True``: optional column hidden until enabled; ``False``: optional but shown.
    optional: bool | None = None
    #: Value → label map for coded values (``state`` columns, enums).
    labels: Mapping[str, str] = field(default_factory=dict)
    #: Link template for the cell, e.g. ``/app/entities/{affected_account.entity_id}``.
    link: str | None = None
    #: Name of a registered UI cell component (e.g. a per-day activity strip);
    #: the cell receives the row value at ``path`` and the result window.
    component: str | None = None
    #: Include every dependency of a derived or custom cell.
    field_categories: frozenset[str] = frozenset()

    def to_json(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"key": self.key, "label": self.label, "kind": self.kind, "path": self.path or self.key}
        if self.link:
            payload["link"] = self.link
        if self.sortable:
            payload["sortable"] = True
        if self.optional is not None:
            payload["hidden_by_default"] = bool(self.optional)
        if self.labels:
            payload["labels"] = dict(self.labels)
        if self.component:
            payload["component"] = self.component
        return payload


@dataclass(frozen=True)
class View:
    """One way to look at the result. Several views are shown as tabs.

    ``source="items"`` is the main paged table; any other ``source`` is a
    named collection in ``result(collections=...)``.
    """

    kind: Literal["table", "chart", "custom"]
    key: str = "table"
    title: str = ""
    source: str = "items"
    #: Columns of a collection table (the main table uses the report's columns).
    columns: tuple[Column, ...] = ()
    chart: Literal["timeseries", "bar", "heatmap"] | None = None
    #: Chart x path and ``(label, y path)`` series over the source rows.
    x: str | None = None
    #: ``chart="heatmap"``: row path of the y category; the first series is the cell value.
    y: str | None = None
    series: tuple[tuple[str, str], ...] = ()
    stacked: bool = False
    #: Shown under the title (how to read this view).
    note: str = ""
    #: ``kind="custom"``: name of a registered UI component that renders the
    #: whole view from the report parameters (e.g. security relation chains).
    component: str | None = None
    access: AccessRule | AccessRequirement | None = None

    def to_json(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"kind": self.kind, "key": self.key, "source": self.source}
        for name in ("title", "chart", "x", "y", "note", "component"):
            if getattr(self, name):
                payload[name] = getattr(self, name)
        if self.columns:
            payload["columns"] = [column.to_json() for column in self.columns]
        if self.series:
            payload["series"] = [{"label": label, "path": path} for label, path in self.series]
        if self.stacked:
            payload["stacked"] = True
        return payload


@dataclass(frozen=True)
class Detail:
    """A per-row drill-down with its own query and columns (e.g. computer → logons)."""

    title: str
    #: Row field whose value identifies the row in ``/rows/{id}/detail``.
    key: str
    columns: tuple[Column, ...]
    #: ``(context, row_id) -> result(...)``; ``context.params`` are the report's params.
    query: Callable[[QueryContext, str], Mapping[str, Any]] | None = None
    #: Alternatively the detail rows are already in the row at this path (no request).
    inline: str | None = None
    #: Name of a registered UI component shown for a selected detail row (e.g. exact evidence).
    row_component: str | None = None
    #: Name of a registered UI component with actions on the whole row
    #: (e.g. a lifecycle form); it calls the domain's own mutation API.
    actions: str | None = None
    row_links: tuple[tuple[str, str], ...] = ()
    default_limit: int = 50
    access: AccessRule | AccessRequirement | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": "inline" if self.inline else "sub",
            "title": self.title,
            "key": self.key,
            "inline": self.inline,
            "row_component": self.row_component,
            "actions": self.actions,
            "columns": [column.to_json() for column in self.columns],
            "row_links": [{"label": label, "href": href} for label, href in self.row_links],
        }


@dataclass(frozen=True)
class AccessRule:
    """Compatibility declaration for the existing domain/delegated readers."""

    report_key: str
    required_fields: frozenset[str] = frozenset()
    #: ``domain``: the query receives the authorised domain ids; ``delegated``:
    #: the report engine enforces scope itself from the access decision.
    scope: Literal["domain", "delegated"] = "domain"
    export_action: str = "export"
    required_capabilities: frozenset[str] = frozenset()

    # Opt in only when the delegated reader enforces generic grants itself.
    accepts_generic_scope: bool = False


@dataclass(frozen=True)
class AccessRequirement:
    """Access declaration for readers that execute the generic scope predicate."""

    access_key: str
    required_fields: frozenset[str] = frozenset()
    required_capabilities: frozenset[str] = frozenset()
    action: str = "view"
    export_action: str = "export"
    #: Installation-wide administration can require both a role and an all grant.
    required_role: str | None = None
    global_scope_only: bool = False

    @property
    def report_key(self) -> str:
        return self.access_key

    @property
    def scope(self) -> str:
        return "generic"


@dataclass(frozen=True)
class QueryContext:
    access: Mapping[str, Any]
    params: Mapping[str, Any]
    #: ``None`` means every domain; only set when ``AccessRule.scope == "domain"``.
    domain_ids: list[int] | None = None
    action: Literal["view", "export"] = "view"
    cursor: str | None = None
    limit: int = 100
    timezone: str = "UTC"
    #: Key of the open view; adapters may build only that collection.
    tab: str | None = None
    sort: str | None = None
    direction: Literal["asc", "desc"] = "asc"
    #: Server-sealed values (never request input), e.g. the storage route authorization.
    runtime: Mapping[str, Any] = field(default_factory=dict)
    #: Atomic category check for this request's complete domain scope.
    field_access: Callable[[frozenset[str]], bool] | None = None
    #: Issued by the server; never reconstructed from client scope parameters.
    scope: AccessScope = field(default_factory=AccessScope)
    principal: Mapping[str, Any] = field(default_factory=dict)

    def scope_filter(self, columns: Mapping[str, str]) -> tuple[str, list[Any]]:
        """Readers apply this before joins, counts, sorting and pagination."""
        return self.scope.sql_filter(columns)

    @property
    def policy_revision(self) -> str:
        return self.scope.policy_revision

    @property
    def decision_id(self) -> str:
        return self.scope.decision_id


@dataclass(frozen=True)
class ReportIntent:
    """Versioned product passport; presentation archetype differs from product purpose.

    Quality fields describe measurement, never assert current source completeness.
    Validation is opt-in for registry checks, not a runtime availability gate.
    """

    version: int
    user_role: str
    question: str
    action: str
    scope: str
    exclusions: str
    sources: tuple[str, ...]
    freshness_expectation: str
    rights: str
    field_classes: tuple[str, ...]
    coverage: str
    completeness: str
    denominator: str
    retention: str
    provenance: str
    primary_archetype: Literal["list", "timeline", "matrix", "summary", "detail", "queue"]
    product_archetype: str = ""
    deterministic_policy: str = ""
    result_limits: str = ""
    fallback: str = ""
    acceptance_lanes: Mapping[str, str] = field(default_factory=dict)
    qualification: Mapping[str, str] = field(default_factory=lambda: {
        "status": "not_applicable", "reason": "No automatic control qualification is asserted by this report.",
    })
    risk: Mapping[str, str] = field(default_factory=lambda: {
        "status": "not_applicable", "reason": "No new risk score or organization risk policy is asserted by this report.",
    })
    confidence: Mapping[str, str] = field(default_factory=lambda: {
        "status": "not_applicable", "reason": "Source quality is reported separately; no confidence score is inferred.",
    })

    def validate(self) -> None:
        if type(self.version) is not int or self.version < 1:
            raise ValueError("report_intent_invalid:version")
        for item in fields(self):
            if item.name == "version":
                continue
            value = getattr(self, item.name)
            if item.name in {"acceptance_lanes", "qualification", "risk", "confidence"}:
                if not isinstance(value, Mapping) or not value:
                    raise ValueError(f"report_intent_invalid:{item.name}")
                values = tuple(value.values())
                if item.name == "acceptance_lanes" and not REQUIRED_ACCEPTANCE_LANES.issubset(value):
                    raise ValueError("report_intent_invalid:acceptance_lanes")
            elif item.name in {"sources", "field_classes"}:
                if not isinstance(value, tuple):
                    raise ValueError(f"report_intent_invalid:{item.name}")
                values = value
            else:
                values = (value,)
            if not values or any(not isinstance(value, str) or not value.strip() for value in values):
                raise ValueError(f"report_intent_invalid:{item.name}")
        if self.primary_archetype not in {"list", "timeline", "matrix", "summary", "detail", "queue"}:
            raise ValueError("report_intent_invalid:primary_archetype")
        if self.product_archetype not in ALLOWED_ARCHETYPES:
            raise ValueError("report_intent_invalid:product_archetype")
        if (not any(source.startswith("Canonical:") and source.removeprefix("Canonical:").strip() for source in self.sources)
                or any(not source.startswith(("Canonical:", "Supplemental:")) for source in self.sources)):
            raise ValueError("report_intent_invalid:sources")

    def to_json(self) -> dict[str, Any]:
        return {"contract_id": "sli.report-intent.v1", **asdict(self),
                "sources": list(self.sources), "field_classes": list(self.field_classes)}

    def to_contract(self, *, report_id: str, name: str, access_key: str,
                    capabilities: Sequence[str] = (), actions: Sequence[str] = ("view",),
                    execution_limits: Mapping[str, Any] | None = None,
                    time_window: str | None = None, status: str = "existing") -> dict[str, Any]:
        """Bridge declaration metadata to all sections of the original intent contract.

        This describes acceptance requirements, not evidence of installed acceptance.
        It neither calls readers nor accepts policy or limits from request input.
        """
        canonical = [source for source in self.sources if source.startswith("Canonical:")]
        supplemental = [source for source in self.sources if source.startswith("Supplemental:")]

        def source_contract(source: str) -> dict[str, str]:
            return {"source_id": source, "authority": source, "permitted_scope": self.scope,
                    "freshness_contract": self.freshness_expectation}

        return {
            "identity": {"report_id": report_id, "name": name, "version": str(self.version),
                         "primary_archetype": self.product_archetype, "product_status": status},
            "user_need": {"primary_user": self.user_role, "question": self.question, "authorized_action": self.action},
            "scope": {"subjects": self.scope, "time_window": time_window or self.scope,
                      "domain_server_scope": self.rights, "exclusions": self.exclusions},
            "sources": {"canonical": [source_contract(source) for source in canonical],
                        "supplemental": [source_contract(source) for source in supplemental]},
            "access": {"required_capability": ", ".join(sorted(capabilities)) or "Server report grant; no extra capability required.",
                       "dataset_or_report_grant": access_key, "server_enforced_scope": self.rights,
                       "permitted_field_classes": list(self.field_classes), "allowed_actions": list(actions)},
            "data_quality": {"coverage_definition": self.coverage, "completeness_definition": self.completeness,
                             "freshness_definition": self.freshness_expectation,
                             "expected_population_or_window": self.denominator, "denominator": self.denominator},
            "observation": {"server_owned_observations": self.provenance, "source_identity": "; ".join(canonical),
                            "evidence_retention_boundary": self.retention},
            "deterministic_policy": self.deterministic_policy,
            "qualification": dict(self.qualification), "risk": dict(self.risk), "confidence": dict(self.confidence),
            "result_limits": {"honest_states": sorted(REQUIRED_HONEST_STATES), "provenance": self.provenance,
                              "coverage_completeness_freshness": self.result_limits,
                              "retention_limits": self.retention, "safe_next_actions": self.action,
                              "execution": dict(execution_limits or {})},
            "views": {"owner_view": self.question, "architecture_review_view": self.deterministic_policy,
                      "auditor_evidence_view": self.provenance},
            "acceptance_lanes": dict(self.acceptance_lanes),
            "ai_assistance": {"mode": "not_applicable", "reason": "Report authority remains deterministic server code."},
            "fallback_and_non_goals": {"deterministic_fallback": self.fallback, "non_goals": self.exclusions},
        }


@dataclass(frozen=True)
class HomeContribution:
    """Reviewed code-only compact reader; discovery follows the report's owner."""

    key: str
    metric_key: str
    label_code: str
    unit_code: str
    definition_version: int = 1
    period_kind: Literal["snapshot", "observations"] = "snapshot"
    meaning: Literal["neutral", "lower_is_better", "higher_is_better"] = "neutral"
    order: int = 100
    required_fields: frozenset[str] = frozenset()
    filters: Mapping[str, str] = field(default_factory=dict)
    reader: Callable[[QueryContext], Mapping[str, Any]] | None = None
    availability: Callable[[], Mapping[str, Any]] | None = None
    attention: Callable[[Mapping[str, Any], str], Sequence[Mapping[str, Any]]] | None = None
    health: bool = True


@dataclass(frozen=True)
class ReportDefinition:
    key: str
    section: str
    title: str
    description: str
    archetype: str
    access: AccessRule | AccessRequirement
    params: tuple[Param, ...]
    columns: tuple[Column, ...]
    query: Callable[[QueryContext], Mapping[str, Any]]
    row_key: str
    views: tuple[View, ...] = (View("table"),)
    #: ``(context) -> (csv_text, {"rows": n, "truncated": bool})``; ``None`` disables export.
    export_csv: Callable[[QueryContext], tuple[str, Mapping[str, Any]]] | None = None
    #: ``(access) -> {param_key: [{value, label}]}`` for ``options_from`` params, sent with the declaration.
    options: Callable[[Mapping[str, Any]], Mapping[str, Sequence[Mapping[str, Any]]]] | None = None
    #: Quick scenarios: ``(label, {param: value})`` applied as a whole filter set.
    presets: tuple[tuple[str, Mapping[str, str]], ...] = ()
    #: Links from a row: ``(label, href template with {path.to.value})``.
    row_links: tuple[tuple[str, str], ...] = ()
    default_limit: int = 100
    max_limit: int = 500
    #: Order of this report's metrics widget on the home page (``None``: not on the home page).
    home_order: int | None = None
    #: Key of a chart view the home widget shows under the metrics (``None``: metrics only).
    home_view: str | None = None
    home_contributions: tuple[HomeContribution, ...] = ()
    #: Name of a registered UI component with page-level actions over the
    #: loaded rows (e.g. choose employees and print a sheet).
    page_actions: str | None = None
    detail: Literal["fields", "none"] | Detail = "fields"
    intent_ref: str | None = None
    intent: ReportIntent | None = None
    #: Dependencies of derived metrics, non-column row paths and series.
    metric_categories: Mapping[str, frozenset[str]] = field(default_factory=dict)
    row_categories: Mapping[str, frozenset[str]] = field(default_factory=dict)
    series_categories: Mapping[str, frozenset[str]] = field(default_factory=dict)

    def intent_contract(self) -> dict[str, Any]:
        """Full product passport with bounds taken from this executable declaration."""
        if self.intent is None:
            raise ValueError(f"report_intent_missing:{self.key}")
        periods = [param for param in self.params if param.kind == "period"]
        return self.intent.to_contract(
            report_id=self.key, name=self.title, access_key=self.access.report_key,
            capabilities=self.access.required_capabilities,
            actions=("view", self.access.export_action) if self.export_csv is not None else ("view",),
            execution_limits={"default": self.default_limit, "max": self.max_limit,
                              "period_max_days": {param.key: param.max_days for param in periods},
                              "detail_default": self.detail.default_limit if isinstance(self.detail, Detail) else None},
            time_window="; ".join(f"{param.key}: default={param.default}, max_days={param.max_days}" for param in periods)
                        or "Latest available snapshot or current projection; see declared source freshness.",
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "result_states": [state.value for state in ResultState],
            "section": self.section,
            "title": self.title,
            "description": self.description,
            "archetype": self.archetype,
            "intent": self.intent.to_json() if self.intent is not None else None,
            "params": [param.to_json() for param in self.params],
            "columns": [column.to_json() for column in self.columns],
            "views": [view.to_json() for view in self.views],
            "row_key": self.row_key,
            "detail": self.detail.to_json() if isinstance(self.detail, Detail) else self.detail,
            "export": self.export_csv is not None,
            "limits": {"default": self.default_limit, "max": self.max_limit},
            "page_actions": self.page_actions,
            "presets": [{"label": label, "params": dict(values)} for label, values in self.presets],
            "row_links": [{"label": label, "href": href} for label, href in self.row_links],
        }


def _first(query: Mapping[str, Sequence[str]], key: str) -> str | None:
    values = query.get(key) or []
    value = values[0] if values else None
    return value.strip() if isinstance(value, str) else value


def _zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError("report_timezone_invalid") from exc


def _instant(text: str | None) -> datetime:
    try:
        moment = datetime.fromisoformat(str(text or "").replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("report_period_invalid") from exc
    if moment.tzinfo is None:
        raise ValueError("report_period_invalid")
    return moment.astimezone(timezone.utc)


def resolve_period(value: Mapping[str, str | None], *, timezone_name: str, max_days: int | None, now: datetime | None = None) -> dict[str, str]:
    """Turns ``period`` (+ ``from``/``to`` calendar dates or exact instants for ``custom``) into a UTC window."""
    preset = value.get("period") or ""
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if preset in PERIOD_PRESETS:
        start, end = current - PERIOD_PRESETS[preset], current
    elif preset == "custom" and "T" in f"{value.get('from') or ''}{value.get('to') or ''}":
        # Exact instants (evidence links): ``to`` is exclusive and both carry an offset.
        start, end = _instant(value.get("from")), _instant(value.get("to"))
        if start >= end:
            raise ValueError("report_period_invalid")
    elif preset == "custom":
        zone = _zone(timezone_name)
        try:
            first = date.fromisoformat(value.get("from") or "")
            last = date.fromisoformat(value.get("to") or "")
        except ValueError as exc:
            raise ValueError("report_period_invalid") from exc
        if first > last:
            raise ValueError("report_period_invalid")
        start = datetime.combine(first, datetime.min.time(), zone).astimezone(timezone.utc)
        end = datetime.combine(last + timedelta(days=1), datetime.min.time(), zone).astimezone(timezone.utc)
    else:
        raise ValueError("report_period_invalid")
    if max_days and end - start > timedelta(days=max_days):
        raise ValueError("report_period_too_wide")
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return {"preset": preset, "from_utc": start.strftime(fmt), "to_utc": end.strftime(fmt)}


def parse_params(definition: ReportDefinition, query: Mapping[str, Sequence[str]], *, now: datetime | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validates request parameters against the declaration.

    Returns ``(params, paging)``. Unknown parameters are rejected so a typo
    never silently widens a query.
    """
    declared = {param.key for param in definition.params}
    period_keys = {"from", "to"} if "period" in declared else set()
    unknown = set(query) - declared - period_keys - RESERVED_KEYS
    if unknown:
        raise ValueError(f"report_parameter_unknown:{min(unknown)}")
    timezone_name = _first(query, "tz") or "UTC"
    _zone(timezone_name)
    params: dict[str, Any] = {}
    for param in definition.params:
        if param.kind == "period":
            raw = {"period": _first(query, "period") or param.default, "from": _first(query, "from"), "to": _first(query, "to")}
            params["period"] = resolve_period(raw, timezone_name=timezone_name, max_days=param.max_days, now=now)
            continue
        if param.kind == "multichoice":
            values = [item.strip() for item in query.get(param.key) or [] if item and item.strip()]
            if param.options and any(item not in {value for value, _ in param.options} for item in values):
                raise ValueError(f"report_parameter_invalid:{param.key}")
            params[param.key] = values
            continue
        value = _first(query, param.key)
        if value in (None, ""):
            value = param.default
        if value in (None, ""):
            if param.required:
                raise ValueError(f"report_parameter_required:{param.key}")
            continue
        if len(str(value)) > param.max_length:
            raise ValueError(f"report_parameter_invalid:{param.key}")
        if param.kind in ("int", "domain"):
            try:
                value = int(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"report_parameter_invalid:{param.key}") from exc
            if value <= 0:
                raise ValueError(f"report_parameter_invalid:{param.key}")
        elif param.kind == "choice" and param.options and value not in {option for option, _ in param.options}:
            raise ValueError(f"report_parameter_invalid:{param.key}")
        params[param.key] = value
    try:
        limit = int(_first(query, "limit") or definition.default_limit)
    except ValueError as exc:
        raise ValueError("report_limit_invalid") from exc
    if not 1 <= limit <= definition.max_limit:
        raise ValueError("report_limit_invalid")
    direction = _first(query, "direction") or "asc"
    if direction not in ("asc", "desc"):
        raise ValueError("report_sort_invalid")
    sort = _first(query, "sort")
    if sort and sort not in {column.key for column in definition.columns if column.sortable}:
        raise ValueError("report_sort_invalid")
    tab = _first(query, "tab")
    if tab and tab not in {view.key for view in definition.views}:
        raise ValueError("report_tab_invalid")
    paging = {"cursor": _first(query, "cursor"), "limit": limit, "timezone": timezone_name, "sort": sort, "direction": direction, "tab": tab}
    return params, paging


def result(
    definition: ReportDefinition, *, state: ResultState | str, items: Sequence[Mapping[str, Any]] = (),
    has_more: bool = False, next_cursor: str | None = None, filtered_count: int | None = None,
    metrics: Sequence[Mapping[str, Any]] = (), series: Mapping[str, Any] | None = None,
    coverage: Mapping[str, Any] | None = None, filter_options: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
    limitations: Sequence[Mapping[str, str]] = (), window: Mapping[str, Any] | None = None,
    collections: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Builds the uniform ``ReportResult`` (ADR 0010 §2)."""
    try:
        state = ResultState(state).value
    except (ValueError, TypeError) as exc:
        raise ValueError("report_state_invalid") from exc
    coverage = dict(coverage or {})
    source_issues = list(coverage.get("source_issues") or [])
    missing_sources = list(coverage.get("missing_sources") or [])
    missing_domains = list(coverage.get("missing_domains") or [])
    for domain in coverage.get("domains") or []:
        if not isinstance(domain, Mapping):
            continue
        statuses = {domain.get(key) for key in ("run_status", "section_status", "state")}
        if statuses & {"failed", "cancelled", "error", "unavailable", "timeout", "denied", "partial", "skipped", "not_collected"} or ("run_status" in domain and not domain.get("run_status")):
            if domain.get("domain_id") is not None and domain["domain_id"] not in missing_domains:
                missing_domains.append(domain["domain_id"])
            if domain.get("section_name") and domain["section_name"] not in missing_sources:
                missing_sources.append(domain["section_name"])
            source = ":".join(str(domain[key]) for key in ("domain_id", "section_name") if domain.get(key) is not None)
            if source:
                source_issues.append({"source": source, **({"source_name": str(domain["domain_name"])} if domain.get("domain_name") else {}),
                                      "reason": domain.get("reason_code") or ("access_denied" if "denied" in statuses else "source_failed" if statuses & {"failed", "cancelled", "error", "unavailable", "timeout"} else "source_partial" if "partial" in statuses else "source_missing"),
                                      "since_utc": domain.get("since_utc") or domain.get("failed_since_utc")})
    for key, reason in (("failed", "source_failed"), ("partial", "source_partial"), ("missing", "source_missing"), ("stale", "snapshot_old")):
        entries = coverage.get(key)
        for source in (entries if isinstance(entries, (list, tuple)) else []):
            if isinstance(source, str) and not any(issue.get("source") == source for issue in source_issues):
                source_issues.append({"source": source, "reason": reason, "since_utc": coverage.get("since_utc")})
    for source in missing_sources:
        if isinstance(source, str) and not any(
            issue.get("source") == source or str(issue.get("source") or "").rsplit(":", 1)[-1] == source
            for issue in source_issues
        ):
            source_issues.append({"source": source, "reason": "source_missing", "since_utc": coverage.get("since_utc")})
    coverage_state = coverage.get("state")
    observed = coverage.get("observed_at_utc") or coverage.get("latest_observed_at_utc")
    stale_since = coverage.get("stale_since_utc")
    threshold = coverage.get("freshness_threshold_seconds")
    if observed and isinstance(threshold, (int, float)) and threshold > 0:
        try:
            observed_at = datetime.fromisoformat(str(observed).replace("Z", "+00:00"))
            expires = observed_at + timedelta(seconds=threshold)
            if observed_at.tzinfo and expires < datetime.now(timezone.utc):
                stale_since = expires.isoformat()
        except (ValueError, OverflowError):
            pass
    # Source/storage failure and access refusal take precedence over coverage.
    # Pending work is a persisted pipeline state, distinct from HTTP loading.
    if state not in {"denied", "error", "not_collected"}:
        if coverage_state in {"failed", "error", "unavailable"}:
            state = "error"
        elif coverage_state == "not_collected":
            state = "partial" if items or any((collections or {}).values()) else "not_collected"
        elif coverage_state == "processing" or coverage.get("unprocessed_events") or (coverage.get("activity") or {}).get("unprocessed_events"):
            state = "processing"
        elif (coverage_state == "stale" or stale_since) and state in {"ok", "empty", "stale"}:
            state = "stale"
        elif state in {"ok", "empty"} and (
            missing_sources or missing_domains or coverage.get("completeness") == "not_proven"
            or coverage_state in {"partial", "unknown", "inactive", "empty_unverified", "coverage_unverified"}
        ):
            state = "partial"
    reasons = {
        "ok": "query_completed", "empty": "query_completed_zero_rows", "denied": "access_denied",
        "not_collected": "collection_not_confirmed", "partial": "coverage_incomplete",
        "processing": "import_or_projection_pending", "stale": "freshness_exceeded", "error": "source_or_storage_error",
    }
    details = {
        "reason": coverage.get("reason") or ("result_truncated" if state == "partial" and coverage.get("truncated") else reasons[state]),
        "source": coverage.get("source"),
        "stage": coverage.get("stage") or "query",
        "limitations": [dict(entry) for entry in limitations],
        "missing_sources": missing_sources, "missing_domains": missing_domains,
        "observed_at_utc": observed, "stale_since_utc": stale_since,
        "source_issues": source_issues,
    }
    return {
        "contract_id": "sli.report-result.v2",
        "report_key": definition.key,
        "state": state,
        "state_message": message(f"reports.state.{state}"),
        "state_details": details,
        "items": list(items),
        "has_more": bool(has_more),
        "next_cursor": next_cursor,
        "filtered_count": filtered_count,
        "metrics": list(metrics),
        "series": dict(series or {}),
        "coverage": coverage,
        "filter_options": {key: list(values) for key, values in (filter_options or {}).items()},
        "limitations": list(limitations),
        "window": dict(window or {}),
        "collections": {key: list(values) for key, values in (collections or {}).items()},
    }


def _read(row: Mapping[str, Any], path: str) -> Any:
    value: Any = row
    for part in path.split("."):
        value = value.get(part) if isinstance(value, Mapping) else None
    return value


def sort_rows(definition: ReportDefinition, rows: Sequence[Mapping[str, Any]], sort: str | None, direction: str = "asc") -> list[Mapping[str, Any]]:
    """Sorts rows by a declared sortable column; empty values always go last."""
    column = next((item for item in definition.columns if item.key == sort and item.sortable), None)
    if column is None:
        return list(rows)
    path = column.path or column.key

    def key(row: Mapping[str, Any]) -> tuple[int, Any]:
        value = _read(row, path)
        if value is None or value == "":
            return (1, "")
        return (0, value.casefold() if isinstance(value, str) else value)

    present = sorted((row for row in rows if key(row)[0] == 0), key=key, reverse=direction == "desc")
    return present + [row for row in rows if key(row)[0] == 1]


def csv_from_columns(columns: Sequence[Column], rows: Sequence[Mapping[str, Any]]) -> str:
    """CSV of the declared columns; formulas are neutralised for spreadsheets."""
    import csv
    import io

    def cell(column: Column, row: Mapping[str, Any]) -> str:
        value = _read(row, column.path or column.key)
        if column.labels and value is not None:
            value = column.labels.get(str(value), value)
        if value is None:
            return ""
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(item) for item in value)
        text = str(value)
        unsafe = text.startswith(("\t", "\r", "\n")) or text.lstrip().startswith(("=", "+", "-", "@"))
        return "'" + text if unsafe else text

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([column.label for column in columns])
    for row in rows:
        writer.writerow([cell(column, row) for column in columns])
    return buffer.getvalue()
