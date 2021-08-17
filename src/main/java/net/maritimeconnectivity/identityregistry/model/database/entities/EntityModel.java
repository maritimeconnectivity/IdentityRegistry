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
package net.maritimeconnectivity.identityregistry.model.database.entities;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import net.maritimeconnectivity.identityregistry.model.database.CertificateModel;
import net.maritimeconnectivity.identityregistry.validators.MCPMRN;
import net.maritimeconnectivity.identityregistry.validators.MRN;
import org.hibernate.validator.constraints.URL;

import javax.persistence.Column;
import javax.persistence.MappedSuperclass;
import java.util.Objects;

@MappedSuperclass
@Getter
@Setter
@ToString
public abstract class EntityModel extends CertificateModel {

    @Column(name = "id_organization", nullable = false)
    private Long idOrganization;

    @MCPMRN
    @Schema(description = "Maritime Connectivity Platform Maritime Resource Name", required = true)
    @Column(name = "mrn", nullable = false)
    private String mrn;

    @MRN
    @Schema(description = "Subsidiary Maritime Resource Name")
    @Column(name = "mrn_subsidiary")
    private String mrnSubsidiary;

    @URL(regexp = "^(http|https).*")
    @Schema(description = "URL of MMS that the identity is registered")
    @Column(name = "home_mms_url")
    private String homeMMSUrl;

    @Schema(description = "Permissions as assigned from the organization")
    @Column(name = "permissions")
    private String permissions;

    /** Copies this entity into the other */
    public EntityModel copyTo(EntityModel entity) {
        Objects.requireNonNull(entity);
        entity.setId(id);
        entity.setIdOrganization(idOrganization);
        entity.setMrn(mrn);
        entity.setPermissions(permissions);
        entity.setMrnSubsidiary(mrnSubsidiary);
        entity.setHomeMMSUrl(homeMMSUrl);
        return entity;
    }

    /** Copies this entity into the other
     * Only update things that are allowed to change on update */
    public EntityModel selectiveCopyTo(EntityModel entity) {
        Objects.requireNonNull(entity);
        entity.setMrn(mrn);
        entity.setPermissions(permissions);
        entity.setMrnSubsidiary(mrnSubsidiary);
        entity.setHomeMMSUrl(homeMMSUrl);
        return entity;
    }

}
