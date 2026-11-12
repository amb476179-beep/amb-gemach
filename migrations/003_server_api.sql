-- 003: טבלאות לשרת (התחברות מכל מכשיר, סנכרון נתונים, בקשות הלוואה, יומן פעילות)
-- תוספות בלבד: לא נמחקת ולא משתנה אף טבלה או עמודה קיימת. בטוח להרצה חוזרת. דורש את 002.
CREATE TABLE IF NOT EXISTS gemach_data (gemach_id uuid PRIMARY KEY REFERENCES gemachim(id) ON DELETE CASCADE, data jsonb NOT NULL DEFAULT '{}', version int NOT NULL DEFAULT 1, updated_at timestamptz NOT NULL DEFAULT now(), updated_by uuid REFERENCES users(id) ON DELETE SET NULL);
CREATE TABLE IF NOT EXISTS sessions (token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
CREATE TABLE IF NOT EXISTS loan_applications (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), gemach_id uuid NOT NULL REFERENCES gemachim(id) ON DELETE CASCADE, data jsonb NOT NULL, status text NOT NULL DEFAULT 'new' CHECK (status IN ('new','approved','rejected')), created_at timestamptz NOT NULL DEFAULT now(), handled_at timestamptz);
CREATE INDEX IF NOT EXISTS loan_applications_gemach_idx ON loan_applications(gemach_id, created_at);
CREATE TABLE IF NOT EXISTS audit_log (id bigserial PRIMARY KEY, gemach_id uuid REFERENCES gemachim(id) ON DELETE CASCADE, user_id uuid REFERENCES users(id) ON DELETE SET NULL, username text, action text NOT NULL, details jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS audit_log_gemach_idx ON audit_log(gemach_id, created_at);
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login timestamptz;
