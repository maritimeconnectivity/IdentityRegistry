ALTER TABLE `certificates` ADD COLUMN `certificate_authority` VARCHAR(255);
UPDATE `certificates` SET `certificate_authority`='urn:mrn:mcl:ca:maritimecloud-idreg';

ALTER TABLE `organizations` ADD COLUMN `certificate_authority` VARCHAR(255);
UPDATE `organizations` SET `certificate_authority`='urn:mrn:mcl:ca:maritimecloud-idreg';
