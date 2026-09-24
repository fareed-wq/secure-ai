-- Create composite index to optimize the Dashboard and Scan History query pattern:
-- .eq('user_id', user.id).order('created_at', { ascending: false })

CREATE INDEX IF NOT EXISTS idx_scans_user_id_created_at
ON public.scans(user_id, created_at DESC);
