/*
 * Copyright 2017 Danish Maritime Authority.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package net.maritimeconnectivity.identityregistry.model.database;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.NoArgsConstructor;
import net.maritimeconnectivity.identityregistry.validators.InPredefinedList;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.util.Objects;

/**
 * Model object representing a role
 */

@Entity
@Table(name = "roles")
@NoArgsConstructor
@Schema(description = "Model object representing a role")
public class Role extends TimestampModel {

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "The role that should be mapped to the permission", allowableValues = "ROLE_SITE_ADMIN, ROLE_ORG_ADMIN, ROLE_ENTITY_ADMIN," +
            "ROLE_USER_ADMIN, ROLE_VESSEL_ADMIN, ROLE_SERVICE_ADMIN, ROLE_DEVICE_ADMIN, ROLE_MMS_ADMIN, ROLE_USER, ROLE_APPROVE_ORG")
    @Column(name = "role_name", nullable = false)
    @InPredefinedList(acceptedValues = {"ROLE_SITE_ADMIN", "ROLE_ORG_ADMIN", "ROLE_ENTITY_ADMIN", "ROLE_USER_ADMIN",
            "ROLE_VESSEL_ADMIN", "ROLE_SERVICE_ADMIN", "ROLE_DEVICE_ADMIN", "ROLE_MMS_ADMIN", "ROLE_USER", "ROLE_APPROVE_ORG"})
    private String roleName;

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "The permission that should be mapped to the role")
    @Column(name = "permission", nullable = false)
    private String permission;

    @Column(name = "id_organization", nullable = false)
    private Long idOrganization;

    /**
     * Copies this role into the other
     */
    public Role copyTo(Role role) {
        Objects.requireNonNull(role);
        role.setId(id);
        role.setIdOrganization(idOrganization);
        role.setPermission(permission);
        role.setRoleName(roleName);
        return role;
    }

    /******************************/
    /** Getters and setters      **/
    /******************************/
    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }

    public String getPermission() {
        return permission;
    }

    public void setPermission(String permission) {
        this.permission = permission;
    }

    public Long getIdOrganization() {
        return idOrganization;
    }

    public void setIdOrganization(Long idOrganization) {
        this.idOrganization = idOrganization;
    }
}
