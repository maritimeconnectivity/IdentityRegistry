/*
 * Copyright 2017 Danish Maritime Authority.
 * Copyright 2020 Maritime Connectivity Platform Consortium
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

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.ToString;
import org.springframework.validation.annotation.Validated;

import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.OneToMany;
import jakarta.persistence.PostPersist;
import jakarta.persistence.PostUpdate;
import jakarta.persistence.PreRemove;
import java.time.Instant;
import java.util.Date;
import java.util.Set;

@MappedSuperclass
@ToString
@Validated
public abstract class CertificateModel extends TimestampModel {

    @PostPersist
    @PostUpdate
    public void setChildIds() {
        if (getCertificates() != null) {
            getCertificates().forEach(this::assignToCert);
        }
    }

    @PreRemove
    public void preRemove() {
        if (getCertificates() != null) {
            Date now = Date.from(Instant.now());
            for (Certificate cert : getCertificates()) {
                // Revoke certificates
                cert.setRevokedAt(now);
                cert.setRevokeReason("cessationofoperation");
                cert.setRevoked(true);
                // Detach certificate from entity - since the model type isn't known, just blank all.
                cert.setOrganization(null);
                cert.setDevice(null);
                cert.setService(null);
                cert.setUser(null);
                cert.setVessel(null);
                cert.setMms(null);
            }
        }
    }

    @OneToMany
    public abstract Set<Certificate> getCertificates();

    @JsonIgnore
    public abstract void assignToCert(Certificate cert); // Do something like cert.set<ModelName>(this)

}
