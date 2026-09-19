CREATE TABLE IF NOT EXISTS public.cpe_cve_cache (
    cpe text PRIMARY KEY,
    cves_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    fetched_at timestamptz NOT NULL DEFAULT timezone('utc'::text, now()),
    expires_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT timezone('utc'::text, now())
);

ALTER TABLE public.cpe_cve_cache ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION atomic_update_cve_status(
    p_scan_id uuid,
    p_expected_status text,
    p_new_status text,
    p_lease_duration_sec integer DEFAULT NULL
) RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    v_report jsonb;
    v_curr_status text;
    v_lease_until timestamptz;
    v_new_report jsonb;
BEGIN
    SELECT report_data INTO v_report FROM public.scans WHERE id = p_scan_id FOR UPDATE;
    IF v_report IS NULL THEN
        RETURN false;
    END IF;

    v_curr_status := v_report->>'cve_enrichment_status';
    IF v_curr_status IS NULL THEN
        v_curr_status := 'NOT_REQUESTED';
    END IF;

    IF v_curr_status IN ('COMPLETED', 'FAILED') THEN
        RETURN false;
    END IF;

    IF p_new_status = 'RUNNING' THEN
        IF v_curr_status = 'QUEUED' OR v_curr_status = 'NOT_REQUESTED' THEN
            -- allowed: normal claim or fast-worker race
        ELSIF v_curr_status = 'RUNNING' THEN
            v_lease_until := (v_report->>'cve_enrichment_lease_until')::timestamptz;
            IF v_lease_until IS NOT NULL AND v_lease_until < now() THEN
                -- allowed reclaim
            ELSE
                RETURN false;
            END IF;
        ELSE
            RETURN false;
        END IF;
    ELSE
        IF v_curr_status != p_expected_status THEN
            RETURN false;
        END IF;
    END IF;

    v_new_report := jsonb_set(
        COALESCE(v_report, '{}'::jsonb),
        '{cve_enrichment_status}',
        to_jsonb(p_new_status)
    );

    IF p_lease_duration_sec IS NOT NULL THEN
        v_new_report := jsonb_set(
            v_new_report,
            '{cve_enrichment_lease_until}',
            to_jsonb((now() + make_interval(secs := p_lease_duration_sec))::text)
        );
    ELSIF p_new_status = 'QUEUED' THEN
        v_new_report := v_new_report - 'cve_enrichment_lease_until';
    END IF;

    UPDATE public.scans SET report_data = v_new_report WHERE id = p_scan_id;
    RETURN true;
END;
$$;

REVOKE EXECUTE ON FUNCTION atomic_update_cve_status(uuid, text, text, integer) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION atomic_update_cve_status(uuid, text, text, integer) FROM anon, authenticated;
GRANT EXECUTE ON FUNCTION atomic_update_cve_status(uuid, text, text, integer) TO service_role;

CREATE OR REPLACE FUNCTION atomic_save_enriched_identities(
    p_scan_id uuid,
    p_expected_status text,
    p_status text,
    p_identities jsonb
) RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    v_report jsonb;
    v_curr_status text;
BEGIN
    SELECT report_data INTO v_report FROM public.scans WHERE id = p_scan_id FOR UPDATE;
    IF v_report IS NULL THEN
        RETURN false;
    END IF;

    v_curr_status := v_report->>'cve_enrichment_status';
    IF v_curr_status IS NULL THEN
        v_curr_status := 'NOT_REQUESTED';
    END IF;

    IF v_curr_status != p_expected_status THEN
        RETURN false;
    END IF;

    UPDATE public.scans
    SET report_data = jsonb_set(
            jsonb_set(
                v_report,
                '{cve_enrichment_status}',
                to_jsonb(p_status)
            ),
            '{technology_identities}',
            p_identities
        )
    WHERE id = p_scan_id;
    RETURN true;
END;
$$;

REVOKE EXECUTE ON FUNCTION atomic_save_enriched_identities(uuid, text, text, jsonb) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION atomic_save_enriched_identities(uuid, text, text, jsonb) FROM anon, authenticated;
GRANT EXECUTE ON FUNCTION atomic_save_enriched_identities(uuid, text, text, jsonb) TO service_role;
