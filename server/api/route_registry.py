"""Реестр HTTP-маршрутов вместо цепочки ``try_handle_*`` (ADR 0014, план 4.3).

Каждый модуль ``server/api/routes/*`` объявляет таблицу ``ROUTES`` из пар
``(метод, шаблон)``, которые он обслуживает:

- ``"/api/x"`` — точный путь;
- ``"/api/x/{}/y"`` — путь с началом ``/api/x/`` и концом ``/y``
  (как ``path.startswith(...) and path.endswith(...)`` в обработчике);
- ``"/api/x/*"`` — любой путь с началом ``/api/x/``.

Реестр выбирает модули по точности совпадения, а не по порядку
регистрации: сначала точный путь, затем шаблон (длиннее известная часть —
раньше), затем префикс (длиннее — раньше). Обработчик модуля может вернуть
``False`` для пути, который его шаблон покрывает, но он не обслуживает; тогда
пробуется следующий кандидат, как раньше в цепочке. Совпадение одного
точного пути у двух модулей запрещено тестом.

Таблица ``ROUTES`` сверяется с условиями в коде обработчиков тестом
``tests/ops/test_route_registry.py``; проверки ролей и capability пока
остаются в ``http_server`` (``route_capability``).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from types import ModuleType

METHODS = ("GET", "POST", "PUT")


def match_rank(pattern: str, path: str) -> tuple[int, int] | None:
    """Ранг совпадения шаблона с путём (меньше — точнее) или ``None``."""
    if pattern.endswith("*"):
        prefix = pattern[:-1]
        return (2, -len(prefix)) if path.startswith(prefix) else None
    if "{}" in pattern:
        start, end = pattern.split("{}", 1)
        return (1, -(len(start) + len(end))) if path.startswith(start) and path.endswith(end) else None
    return (0, 0) if path == pattern else None


class RouteRegistry:
    """Модули маршрутов и их таблицы ``ROUTES``."""

    def __init__(self, modules: Sequence[ModuleType]) -> None:
        self._entries: list[tuple[int, ModuleType, str, str]] = []
        for order, module in enumerate(modules):
            for method, pattern in getattr(module, "ROUTES"):
                if method not in METHODS:
                    raise ValueError(f"unsupported method {method!r} in {module.__name__}")
                self._entries.append((order, module, method, pattern))

    def entries(self) -> Iterable[tuple[ModuleType, str, str]]:
        return ((module, method, pattern) for _, module, method, pattern in self._entries)

    def candidates(self, method: str, path: str) -> list[ModuleType]:
        """Модули, чьи шаблоны покрывают путь, от самого точного совпадения."""
        best: dict[str, tuple[tuple[int, int], int, ModuleType]] = {}
        for order, module, entry_method, pattern in self._entries:
            if entry_method != method:
                continue
            rank = match_rank(pattern, path)
            if rank is None:
                continue
            key = module.__name__
            current = best.get(key)
            if current is None or (rank, order) < (current[0], current[1]):
                best[key] = (rank, order, module)
        return [module for _, _, module in sorted(best.values(), key=lambda item: (item[0], item[1]))]

    def dispatch_get(self, handler: object, path: str, query: dict) -> bool:
        for module in self.candidates("GET", path):
            if module.try_handle_get(handler, path, query):
                return True
        return False

    def dispatch_post(self, handler: object, path: str) -> bool:
        for module in self.candidates("POST", path):
            if module.try_handle_post(handler, path):
                return True
        return False

    def dispatch_put(self, handler: object, path: str) -> bool:
        for module in self.candidates("PUT", path):
            if module.try_handle_put(handler, path):
                return True
        return False
