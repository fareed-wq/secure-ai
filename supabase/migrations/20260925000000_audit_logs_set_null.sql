-- Migration: Account Deletion Fix for Audit Logs
-- Description: Changes the audit_logs admin_user_id foreign key constraint to ON DELETE SET NULL
-- This preserves historical audit data while allowing admin accounts to be deleted.

DO $$
DECLARE
    rec_record RECORD;
BEGIN
    -- Drop existing foreign key for audit_logs -> auth.users
    FOR rec_record IN
        SELECT tc.constraint_name
        FROM information_schema.table_constraints AS tc
        JOIN information_schema.key_column_usage AS kcu
          ON tc.constraint_name = kcu.constraint_name
          AND tc.table_schema = kcu.table_schema
        WHERE tc.constraint_type = 'FOREIGN KEY'
          AND tc.table_name = 'audit_logs'
          AND kcu.column_name = 'admin_user_id'
    LOOP
        EXECUTE 'ALTER TABLE public.audit_logs DROP CONSTRAINT ' || quote_ident(rec_record.constraint_name);
    END LOOP;
END $$;

-- Make admin_user_id nullable (it should be already, but just to be safe)
ALTER TABLE public.audit_logs ALTER COLUMN admin_user_id DROP NOT NULL;

-- Re-add constraint with ON DELETE SET NULL
ALTER TABLE public.audit_logs
ADD CONSTRAINT audit_logs_admin_user_id_fkey
FOREIGN KEY (admin_user_id) REFERENCES auth.users(id) ON DELETE SET NULL;
