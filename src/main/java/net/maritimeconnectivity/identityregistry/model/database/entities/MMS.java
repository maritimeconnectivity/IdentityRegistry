/*
 * Copyright 2020 Maritime Connectivity Platform Consortium.
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
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import net.maritimeconnectivity.identityregistry.model.database.Certificate;
import org.hibernate.validator.constraints.URL;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import java.util.Set;

import static io.swagger.v3.oas.annotations.media.Schema.AccessMode.READ_ONLY;

/**
 * Model object representing Maritime Messaging Service (MMS) instance
 */

@Entity
@Table(name = "mmses")
@Getter
@Setter
@ToString
@NoArgsConstructor
@Schema(description = "Model object representing an MMS")
public class MMS extends NonHumanEntityModel {

    @NotNull
    @URL(regexp = "^(http|https).*")
    @Schema(description = "URL of MMS instance", requiredMode = Schema.RequiredMode.REQUIRED)
    @Column(name = "url", nullable = false)
    private String url;

    @OneToMany(fetch = FetchType.EAGER, mappedBy = "mms")
    @Schema(description = "The set of certificates of the MMS. Cannot be created/updated by editing in the model. Use the dedicated create and revoke calls.", accessMode = READ_ONLY)
    private Set<Certificate> certificates;

    /**
     * Copies this mms into the other
     */
    @Override
    public MMS copyTo(EntityModel target) {
        MMS mms = (MMS) super.copyTo(target);
        mms.getCertificates().clear();
        mms.getCertificates().addAll(certificates);
        mms.setChildIds();
        mms.setUrl(url);
        return mms;
    }

    /**
     * Copies this mms into the other
     * Only update things that are allowed to change on update
     */
    @Override
    public MMS selectiveCopyTo(EntityModel target) {
        MMS mms = (MMS) super.selectiveCopyTo(target);
        mms.setChildIds();
        mms.setUrl(url);
        return mms;
    }

    public void assignToCert(Certificate cert) {
        cert.setMms(this);
    }
}

