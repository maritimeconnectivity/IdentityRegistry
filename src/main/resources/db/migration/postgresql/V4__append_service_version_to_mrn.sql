BEGIN;
UPDATE services SET mrn = mrn || ':' || instance_version, updated_at = now() WHERE instance_version != '';
ALTER TABLE services DROP COLUMN instance_version CASCADE;
ALTER TABLE services ADD CONSTRAINT unique_mrn UNIQUE (mrn);
COMMIT;