-- 002: משתמשי צוות לכל גמ"ח + צ'אט שירות לקוחות
-- תוספות בלבד: לא נמחקת אף טבלה או עמודה קיימת. בטוח להרצה חוזרת.
BEGIN;

-- 1) משתמשי צוות (staff) עם רמת הרשאה, בנוסף ל-owner ו-gemach הקיימים
ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS permission text NOT NULL DEFAULT 'full';
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_permission_check;
ALTER TABLE users ADD CONSTRAINT users_permission_check CHECK (permission IN ('full','edit','view'));
-- הרחבת אילוצי התפקיד כך שיכללו גם staff (השורות הקיימות ממשיכות לעבור)
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('owner','gemach','staff'));
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_check;
ALTER TABLE users ADD CONSTRAINT users_check CHECK ((role = 'owner' AND gemach_id IS NULL) OR (role IN ('gemach','staff') AND gemach_id IS NOT NULL));

-- 2) צ'אט שירות לקוחות: שיחה אחת לכל גמ"ח מול מנהל המערכת
CREATE TABLE IF NOT EXISTS support_messages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  gemach_id uuid NOT NULL REFERENCES gemachim(id) ON DELETE CASCADE,
  sender_role text NOT NULL CHECK (sender_role IN ('gemach','owner')),
  sender_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  body text NOT NULL CHECK (char_length(body) BETWEEN 1 AND 2000),
  read_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS support_messages_gemach_idx ON support_messages(gemach_id, created_at);
CREATE INDEX IF NOT EXISTS support_messages_unread_idx ON support_messages(sender_role, read_at) WHERE read_at IS NULL;

-- 3) הגדרות טכניות לכל גמ"ח (למשל ניתוק אוטומטי)
ALTER TABLE gemachim ADD COLUMN IF NOT EXISTS settings jsonb NOT NULL DEFAULT '{}';

COMMIT;
-- הפרדה בין גמחים: כל שאילתה בשרת חייבת לסנן לפי gemach_id של המשתמש המחובר;
-- רק משתמש owner רשאי לקרוא את support_messages של כל הגמחים.
