-- Migration: Scan Shares
CREATE TABLE IF NOT EXISTS public.scan_shares (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id uuid NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    owner_user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    share_token text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz NULL
);

-- Partial unique index to enforce one active share per scan
CREATE UNIQUE INDEX idx_scan_shares_one_active
ON public.scan_shares (scan_id)
WHERE revoked_at IS NULL;

-- Enable RLS
ALTER TABLE public.scan_shares ENABLE ROW LEVEL SECURITY;

-- Owner can view their own shares
CREATE POLICY "Users can view own shares"
ON public.scan_shares
FOR SELECT
TO authenticated
USING (auth.uid() = owner_user_id);

-- Owner can insert a share for their own scan
CREATE POLICY "Users can insert own shares"
ON public.scan_shares
FOR INSERT
TO authenticated
WITH CHECK (
    auth.uid() = owner_user_id 
    AND EXISTS (
        SELECT 1 FROM public.scans 
        WHERE scans.id = scan_id AND scans.user_id = auth.uid()
    )
);

-- Owner can update (revoke) their own shares
CREATE POLICY "Users can update own shares"
ON public.scan_shares
FOR UPDATE
TO authenticated
USING (auth.uid() = owner_user_id);
