BEGIN;
UPDATE `services` SET `mrn` = CONCAT(`mrn`, ':', `instance_version`), `updated_at` = NOW() WHERE `instance_version` != '';
ALTER TABLE `services` DROP COLUMN `instance_version`;
COMMIT;
