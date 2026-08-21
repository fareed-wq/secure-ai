import pytest

def test_delete_does_not_consume_quota():
    from api.index import app
    routes = [r.path for r in app.routes]
    assert "/api/scan/delete" not in routes

def test_rls_migration_exists():
    import os
    migrations_dir = "supabase/migrations"
    migrations = os.listdir(migrations_dir)
    found_delete_policy = False
    for m in migrations:
        with open(os.path.join(migrations_dir, m), 'r', encoding='utf-8') as f:
            content = f.read()
            if "FOR DELETE" in content and ("public.scans" in content or "history_delete_rls" in m):
                found_delete_policy = True
                break
    assert found_delete_policy, "Migration for DELETE policy must exist"
