"""Compatibility alias for the database-free acquisition implementation."""
from __future__ import annotations

import sys

from sli_collect import radius_contract as _implementation

# Preserve one module object, including private helpers patched by callers.
sys.modules[__name__] = _implementation
