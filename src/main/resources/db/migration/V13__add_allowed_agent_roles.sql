CREATE TABLE `allowed_agent_roles` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `id_agent` INT,
    `role_name` VARCHAR(255),
    `created_at` DATETIME,
    `updated_at` DATETIME,
    PRIMARY KEY (`id`),
    FOREIGN KEY (`id_agent`) REFERENCES acting_on_behalf(`id`)
);
