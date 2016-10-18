/* Copyright 2016 Danish Maritime Authority.
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
package net.maritimecloud.identityregistry.model.database;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.annotations.ApiModelProperty;

import java.util.Objects;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;

/**
 * Model object representing a certificate
 */

@Entity
@Table(name="roles")
public class Role extends TimestampModel {

    public Role() {
    }

    @ApiModelProperty(required = true, value = "The role that should be mapped to the permission", allowableValues = "ROLE_ORG_ADMIN, ROLE_USER")
    @Column(name = "role_name")
    private String roleName;

    @ApiModelProperty(required = true, value = "The permission that should be mapped to the role")
    @Column(name = "permission")
    private String permission;

    @JsonIgnore
    @Column(name = "id_organization")
    private Long idOrganization;

    /** Copies this user into the other */
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
