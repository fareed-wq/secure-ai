import pytest
import os

@pytest.fixture(autouse=True)
def preserve_dependency_overrides():
    """Snapshot and restore FastAPI dependency overrides per test to prevent global state corruption."""
    from api.index import app
    original_overrides = app.dependency_overrides.copy()
    try:
        yield
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(original_overrides)

# --- Legacy ModuleResult Compatibility ---
from api.scanner.core import ModuleResult

def _module_result_iter(self):
    return iter(self.findings)

def _module_result_len(self):
    return len(self.findings)

def _module_result_getitem(self, index):
    return self.findings[index]

ModuleResult.__iter__ = _module_result_iter
ModuleResult.__len__ = _module_result_len
ModuleResult.__getitem__ = _module_result_getitem


def _module_result_str(self):
    return str(self.findings)

def _module_result_repr(self):
    return repr(self.findings)

def _module_result_bool(self):
    return bool(self.findings)

ModuleResult.__str__ = _module_result_str
ModuleResult.__repr__ = _module_result_repr
ModuleResult.__bool__ = _module_result_bool

def _module_result_extend(self, iterable):
    self.findings.extend(iterable)

ModuleResult.extend = _module_result_extend

def _module_result_add(self, other):
    return self.findings + list(other)

def _module_result_radd(self, other):
    return list(other) + self.findings

ModuleResult.__add__ = _module_result_add
ModuleResult.__radd__ = _module_result_radd
