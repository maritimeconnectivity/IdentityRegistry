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
package net.maritimecloud.identityregistry.model.database.entities;

import net.maritimecloud.identityregistry.model.database.CertificateModel;

import javax.persistence.Column;
import javax.persistence.MappedSuperclass;
import java.util.Objects;

@MappedSuperclass
public abstract class EntityModel extends CertificateModel {
    @Column(name = "id_organization")
    private Long idOrganization;

    @Column(name = "mrn")
    private String mrn;

    @Column(name = "permissions")
    private String permissions;

    /** Copies this entity into the other */
    public EntityModel copyTo(EntityModel entity) {
        Objects.requireNonNull(entity);
        entity.setId(id);
        entity.setIdOrganization(idOrganization);
        entity.setMrn(mrn);
        entity.setPermissions(permissions);
        return entity;
    }

    /** Copies this entity into the other
     * Only update things that are allowed to change on update */
    public EntityModel selectiveCopyTo(EntityModel entity) {
        Objects.requireNonNull(entity);
        entity.setMrn(mrn);
        entity.setPermissions(permissions);
        return entity;
    }

    /******************************/
    /** Getters and setters      **/
    /******************************/
    public Long getIdOrganization() {
        return idOrganization;
    }

    public void setIdOrganization(Long idOrganization) {
        this.idOrganization = idOrganization;
    }

    public String getMrn() {
        return mrn;
    }

    public void setMrn(String mrn) {
        this.mrn = mrn;
    }

    public String getPermissions() {
        return permissions;
    }

    public void setPermissions(String permissions) {
        this.permissions = permissions;
    }
}
