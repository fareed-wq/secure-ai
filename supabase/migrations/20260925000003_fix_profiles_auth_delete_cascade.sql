-- Migration: Fix profiles -> auth.users ON DELETE CASCADE
-- Description: The previous migration (20260924140000) attempted to dynamically drop and recreate this constraint, but it appears the constraint `profiles_id_fkey` remained without the CASCADE rule in production. This explicitly targets `profiles_id_fkey` to ensure it is correctly defined.

ALTER TABLE public.profiles
DROP CONSTRAINT IF EXISTS profiles_id_fkey;

ALTER TABLE public.profiles
ADD CONSTRAINT profiles_id_fkey
FOREIGN KEY (id) REFERENCES auth.users(id) ON DELETE CASCADE;
