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
