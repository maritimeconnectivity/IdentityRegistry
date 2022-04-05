ALTER TABLE `vessel_attributes` CHANGE COLUMN `end` `valid_until` DATETIME;

ALTER TABLE `certificates` CHANGE COLUMN `end` `valid_until` DATETIME;
