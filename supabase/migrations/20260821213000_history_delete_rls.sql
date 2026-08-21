-- Create DELETE policy for public.scans to allow users to delete their own history
CREATE POLICY "Users can delete own scans"
ON public.scans
FOR DELETE
TO authenticated
USING (auth.uid() = user_id);
