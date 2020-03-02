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

import io.swagger.annotations.ApiModelProperty;
import net.maritimecloud.identityregistry.model.database.Certificate;

import javax.persistence.*;
import java.util.Set;

/**
 * Model object representing mms
 */

@Entity
@Table(name = "mms")
public class MMS extends NonHumanEntityModel {
    public MMS() {
    }

    @ApiModelProperty(value = "URL of MMS instance")
    @Column(name = "url")
    private String url;

    @OneToMany(fetch = FetchType.EAGER, mappedBy = "mms")
    @ApiModelProperty(value = "Cannot be created/updated by editing in the model. Use the dedicate create and revoke calls.")
    private Set<Certificate> certificates;

    /** Copies this device into the other */
    @Override
    public MMS copyTo(EntityModel target) {
        MMS mms = (MMS) super.copyTo(target);
        mms.getCertificates().clear();
        mms.getCertificates().addAll(certificates);
        mms.setChildIds();
        return mms;
    }

    /** Copies this device into the other
     * Only update things that are allowed to change on update */
    @Override
    public MMS selectiveCopyTo(EntityModel target) {
        MMS device = (MMS) super.selectiveCopyTo(target);
        device.setChildIds();
        return device;
    }

    public void assignToCert(Certificate cert){
        cert.setMms(this);
    }

    /******************************/
    /** Getters and setters      **/
    /******************************/
    public Set<Certificate> getCertificates() {
        return certificates;
    }
}

