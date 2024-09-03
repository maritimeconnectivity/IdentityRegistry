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
package net.maritimeconnectivity.identityregistry.model.database.entities;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import net.maritimeconnectivity.identityregistry.model.database.Certificate;

import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import java.util.Set;

import static io.swagger.v3.oas.annotations.media.Schema.AccessMode.READ_ONLY;

/**
 * Model object representing a device
 */

@Entity
@Table(name = "devices")
@Schema(description = "Model object representing a device")
@NoArgsConstructor
public class Device extends NonHumanEntityModel {

    @Getter
    @Setter
    @OneToMany(fetch = FetchType.EAGER, mappedBy = "device")
    @Schema(description = "The set of certificates of the device. Cannot be created/updated by editing in the model. Use the dedicated create and revoke calls.", accessMode = READ_ONLY)
    private Set<Certificate> certificates;

    /**
     * Copies this device into the other
     */
    @Override
    public Device copyTo(EntityModel target) {
        Device device = (Device) super.copyTo(target);
        device.getCertificates().clear();
        device.getCertificates().addAll(certificates);
        device.setChildIds();
        return device;
    }

    /**
     * Copies this device into the other
     * Only update things that are allowed to change on update
     */
    @Override
    public Device selectiveCopyTo(EntityModel target) {
        Device device = (Device) super.selectiveCopyTo(target);
        device.setChildIds();
        return device;
    }

    public void assignToCert(Certificate cert) {
        cert.setDevice(this);
    }
}

