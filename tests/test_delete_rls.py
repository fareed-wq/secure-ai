import pytest
import os

def test_delete_does_not_consume_quota():
    from api.index import app
    routes = [r.path for r in app.routes]
    assert "/api/scan/delete" not in routes

def test_rls_migration_exists():
    filepath = "supabase/migrations/20260821213000_history_delete_rls.sql"
    assert os.path.exists(filepath), f"Migration file {filepath} not found"
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
        
    assert "CREATE POLICY" in content
    assert "FOR DELETE" in content
    assert "ON public.scans" in content
    assert "TO authenticated" in content
    assert "auth.uid() = user_id" in content

