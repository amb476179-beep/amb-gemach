-- 005: מסמכים בארון קבצים (Object Storage), יומן גיבויים, ואימות דו-שלבי (TOTP)
CREATE TABLE IF NOT EXISTS doc_files (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  gemach_id uuid NOT NULL REFERENCES gemachim(id) ON DELETE CASCADE,
  name text NOT NULL,
  content_type text NOT NULL DEFAULT 'application/octet-stream',
  size int NOT NULL DEFAULT 0,
  created_by uuid,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS doc_files_gemach_idx ON doc_files(gemach_id);
CREATE TABLE IF NOT EXISTS backup_runs (
  id bigserial PRIMARY KEY,
  run_at timestamptz NOT NULL DEFAULT now(),
  day text NOT NULL,
  gemachim int NOT NULL DEFAULT 0,
  ok boolean NOT NULL DEFAULT true,
  note text
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_on boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last bigint NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_hashes jsonb NOT NULL DEFAULT '[]';
CREATE TABLE IF NOT EXISTS sys_kv (k text PRIMARY KEY, v text NOT NULL);
-- (הטוקן של הגיבוי הלילי נשמר כאן כ-hash בלבד, ומוגדר ידנית: INSERT INTO sys_kv ... 'cron_backup')
