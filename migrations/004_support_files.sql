-- 004: קבצים מצורפים בצ'אט שירות הלקוחות (תוספות בלבד, בטוח להרצה חוזרת)
ALTER TABLE support_messages ADD COLUMN IF NOT EXISTS file_name text;
ALTER TABLE support_messages ADD COLUMN IF NOT EXISTS file_type text;
ALTER TABLE support_messages ADD COLUMN IF NOT EXISTS file_data text;
-- חסימת גישת מנהל המערכת לנתוני גמ"ח נשמרת ב-gemachim.settings (owner_access), שכבר קיים מ-002
