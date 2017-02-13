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
package net.maritimecloud.identityregistry.model.database.entities;

import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import io.swagger.annotations.ApiModelProperty;
import net.maritimecloud.identityregistry.model.database.Certificate;
import org.hibernate.validator.constraints.NotBlank;

/**
 * Model object representing a device
 */

@Entity
@Table(name = "devices")
public class Device extends NonHumanEntityModel {

    public Device() {
    }

    @OneToMany(mappedBy = "device")
    @ApiModelProperty(value = "Cannot be created/updated by editing in the model. Use the dedicate create and revoke calls.")
    //@Where(clause="UTC_TIMESTAMP() BETWEEN start AND end")
    private List<Certificate> certificates;

    /** Copies this device into the other */
    public Device copyTo(EntityModel target) {
        Device device = (Device) super.copyTo(target);
        device.getCertificates().clear();
        device.getCertificates().addAll(certificates);
        device.setChildIds();
        return device;
    }

    /** Copies this device into the other
     * Only update things that are allowed to change on update */
    public Device selectiveCopyTo(EntityModel target) {
        Device device = (Device) super.selectiveCopyTo(target);
        device.setChildIds();
        return device;
    }

    public void assignToCert(Certificate cert){
        cert.setDevice(this);
    }

    /******************************/
    /** Getters and setters      **/
    /******************************/
    public List<Certificate> getCertificates() {
        return certificates;
    }
}

