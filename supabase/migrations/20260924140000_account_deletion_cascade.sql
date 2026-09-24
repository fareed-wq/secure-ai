-- Migration: Add ON DELETE CASCADE to user-owned core tables

DO $$
DECLARE
    rec_record RECORD;
BEGIN
    -- Drop existing foreign keys for profiles -> auth.users
    FOR rec_record IN
        SELECT tc.constraint_name
        FROM information_schema.table_constraints AS tc
        JOIN information_schema.key_column_usage AS kcu
          ON tc.constraint_name = kcu.constraint_name
          AND tc.table_schema = kcu.table_schema
        WHERE tc.constraint_type = 'FOREIGN KEY'
          AND tc.table_name = 'profiles'
          AND kcu.column_name = 'id'
    LOOP
        EXECUTE 'ALTER TABLE public.profiles DROP CONSTRAINT ' || quote_ident(rec_record.constraint_name);
    END LOOP;

    -- Drop existing foreign keys for scans -> auth.users
    FOR rec_record IN
        SELECT tc.constraint_name
        FROM information_schema.table_constraints AS tc
        JOIN information_schema.key_column_usage AS kcu
          ON tc.constraint_name = kcu.constraint_name
          AND tc.table_schema = kcu.table_schema
        WHERE tc.constraint_type = 'FOREIGN KEY'
          AND tc.table_name = 'scans'
          AND kcu.column_name = 'user_id'
    LOOP
        EXECUTE 'ALTER TABLE public.scans DROP CONSTRAINT ' || quote_ident(rec_record.constraint_name);
    END LOOP;
END $$;

-- Re-add constraints with ON DELETE CASCADE
ALTER TABLE public.profiles
ADD CONSTRAINT profiles_id_fkey
FOREIGN KEY (id) REFERENCES auth.users(id) ON DELETE CASCADE;

ALTER TABLE public.scans
ADD CONSTRAINT scans_user_id_fkey
FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE;
