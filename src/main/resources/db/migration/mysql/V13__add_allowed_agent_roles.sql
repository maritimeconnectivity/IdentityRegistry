CREATE TABLE `allowed_agent_roles` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `id_agent` INT,
    `role_name` VARCHAR(255),
    `created_at` DATETIME,
    `updated_at` DATETIME,
    PRIMARY KEY (`id`),
    FOREIGN KEY (`id_agent`) REFERENCES acting_on_behalf(`id`)
);

DROP PROCEDURE IF EXISTS `addAllowedRoleToExistingAgents`;
DELIMITER //
CREATE PROCEDURE `addAllowedRoleToExistingAgents`()
BEGIN
    DECLARE agentId INT;
    DECLARE roleName VARCHAR(255) DEFAULT 'ROLE_ORG_ADMIN';
    DECLARE now DATETIME DEFAULT NOW();
    DECLARE done INT DEFAULT FALSE;
    DECLARE cursorAgentId CURSOR FOR SELECT id from `acting_on_behalf`;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;
    OPEN cursorAgentId;
    loop_through_rows: LOOP
        FETCH cursorAgentId INTO agentId;
        IF done THEN
            LEAVE loop_through_rows;
        END IF;
        INSERT INTO `allowed_agent_roles`(id_agent, role_name, created_at, updated_at)
        VALUES (agentId, roleName, now, now);
    END LOOP;
    CLOSE cursorAgentId;
END;
//
DELIMITER ;
CALL `addAllowedRoleToExistingAgents`();
DROP PROCEDURE IF EXISTS `addAllowedRoleToExistingAgents`;
