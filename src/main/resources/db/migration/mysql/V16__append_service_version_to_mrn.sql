BEGIN;
UPDATE `services` SET `mrn` = `mrn` + ':' + `instance_version` WHERE `instance_version` != '';
ALTER TABLE `services` DROP COLUMN `instance_version`;
COMMIT;
