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

import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.OneToMany;
import javax.persistence.PostPersist;
import javax.persistence.PostUpdate;
import javax.persistence.Table;

import io.swagger.annotations.ApiModelProperty;
import net.maritimecloud.identityregistry.model.database.Certificate;

/**
 * Model object representing a vessel
 */

@Entity
@Table(name = "vessels")
public class Vessel extends NonHumanEntityModel {

    public Vessel() {
    }

    @OneToMany(cascade = CascadeType.ALL, mappedBy = "vessel", orphanRemoval=true)
    private List<VesselAttribute> attributes;

    @ApiModelProperty(value = "Cannot be created/updated by editing in the model. Use the dedicate create and revoke calls.")
    @OneToMany(mappedBy = "vessel", orphanRemoval=false)
    //@Where(clause="UTC_TIMESTAMP() BETWEEN start AND end")
    private List<Certificate> certificates;

    /** Copies this vessel into the other */
    public Vessel copyTo(EntityModel target) {
        Vessel vessel = (Vessel) super.copyTo(target);
        vessel.getAttributes().clear();
        vessel.getAttributes().addAll(attributes);
        vessel.getCertificates().clear();
        vessel.getCertificates().addAll(certificates);
        vessel.setChildIds();
        return vessel;
    }

    /** Copies this vessel into the other
     * Only update things that are allowed to change on update */
    @Override
    public Vessel selectiveCopyTo(EntityModel target) {
        Vessel vessel = (Vessel) super.selectiveCopyTo(target);
        vessel.getAttributes().clear();
        vessel.getAttributes().addAll(attributes);
        vessel.setChildIds();
        return vessel;
    }

    @PostPersist
    @PostUpdate
    public void setChildIds() {
        super.setChildIds();
        if (this.attributes != null) {
            for (VesselAttribute attr : this.attributes) {
                attr.setVessel(this);
            }
        }
    }

    public void assignToCert(Certificate cert){
        cert.setVessel(this);
    }

    /******************************/
    /** Getters and setters      **/
    /******************************/
    public List<VesselAttribute> getAttributes() {
        return attributes;
    }

    public void setAttributes(List<VesselAttribute> attributes) {
        this.attributes = attributes;
    }

    public List<Certificate> getCertificates() {
        return certificates;
    }
}
