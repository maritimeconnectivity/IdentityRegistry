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

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import net.maritimeconnectivity.identityregistry.model.database.Certificate;
import net.maritimeconnectivity.identityregistry.model.database.VesselImage;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.PostPersist;
import javax.persistence.PostUpdate;
import javax.persistence.Table;
import javax.validation.Valid;
import java.util.Set;

/**
 * Model object representing a vessel
 */

@Entity
@Table(name = "vessels")
@Getter
@Setter
@ToString(exclude = "services")
public class Vessel extends NonHumanEntityModel {

    public Vessel() {
    }

    @OneToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL, mappedBy = "vessel", orphanRemoval=true)
    private Set<@Valid VesselAttribute> attributes;

    @Schema(description = "Cannot be created/updated by editing in the model. Use the dedicate create and revoke calls.")
    @OneToMany(fetch = FetchType.EAGER, mappedBy = "vessel")
    private Set<Certificate> certificates;

    @JsonIgnore
    @OneToMany(fetch = FetchType.EAGER, mappedBy = "vessel")
    private Set<Service> services;

    @JsonIgnore
    @OneToOne(cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name="id_image")
    private VesselImage image;

    /** Copies this vessel into the other */
    @Override
    public Vessel copyTo(EntityModel target) {
        Vessel vessel = (Vessel) super.copyTo(target);
        vessel.getAttributes().clear();
        vessel.getAttributes().addAll(attributes);
        vessel.setImage(this.image);
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

    @Override
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
}
