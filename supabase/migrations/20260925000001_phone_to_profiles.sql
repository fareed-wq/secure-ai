-- Migration: Move phone to profiles
-- Description: Adds a phone column to public.profiles, migrates existing phone data from auth.users, and removes the phone identity from auth.users to allow duplicate phone numbers across different email accounts.

ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS phone text;

DO $$
BEGIN
    UPDATE public.profiles p
    SET phone = u.phone
    FROM auth.users u
    WHERE u.id = p.id AND u.phone IS NOT NULL;
END $$;

UPDATE auth.users SET phone = NULL WHERE phone IS NOT NULL;
