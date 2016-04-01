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
package net.maritimecloud.identityregistry.model;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.TimeZone;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.OneToMany;
import javax.persistence.PostPersist;
import javax.persistence.PostUpdate;
import javax.persistence.PreRemove;
import javax.persistence.Table;

import org.hibernate.annotations.Where;

/**
 * Model object representing a vessel
 */

@Entity
@Table(name = "vessels")
public class Vessel extends TimestampModel {

    public Vessel() {
    }

    @JsonIgnore
    @Column(name = "id_organization")
    private Long idOrganization;

    @Column(name = "vessel_org_id")
    private String vesselOrgId;

    @Column(name = "name")
    private String name;

    @OneToMany(cascade = CascadeType.REMOVE, mappedBy = "vessel", orphanRemoval=true)
    private List<VesselAttribute> attributes;

    @OneToMany(mappedBy = "vessel", orphanRemoval=false)
    //@Where(clause="UTC_TIMESTAMP() BETWEEN start AND end")
    private List<Certificate> certificates;

    /** Copies this vessel into the other */
    public Vessel copyTo(Vessel vessel) {
        Objects.requireNonNull(vessel);
        vessel.setId(id);
        vessel.setIdOrganization(idOrganization);
        vessel.setName(name);
        vessel.setVesselOrgId(vesselOrgId);
        vessel.getAttributes().clear();
        vessel.getAttributes().addAll(attributes);
        vessel.getCertificates().clear();
        vessel.getCertificates().addAll(certificates);
        vessel.setChildIds();
        return vessel;
    }

    /** Copies this vessel into the other
     * Only update things that are allowed to change on update */
    public Vessel selectiveCopyTo(Vessel vessel) {
        vessel.setName(name);
        vessel.setVesselOrgId(vesselOrgId);
        vessel.getAttributes().clear();
        vessel.getAttributes().addAll(attributes);
        vessel.setChildIds();
        return vessel;
    }

    @PostPersist
    @PostUpdate
    void setChildIds() {
        if (this.attributes != null) {
            for (VesselAttribute attr : this.attributes) {
                attr.setVessel(this);
            }
        }
        if (this.certificates != null) {
            for (Certificate cert : this.certificates) {
                cert.setVessel(this);
            }
        }
    }

    @PreRemove
    public void preRemove() {
        if (this.certificates != null) {
            // Dates are converted to UTC before saving into the DB
            Calendar cal = Calendar.getInstance();
            long offset = cal.get(Calendar.ZONE_OFFSET) + cal.get(Calendar.DST_OFFSET);
            Date now = new Date(cal.getTimeInMillis() - offset);
            for (Certificate cert : this.certificates) {
                // Revoke certificates
                cert.setRevokedAt(now);
                cert.setEnd(now);
                cert.setRevokeReason("cessationofoperation");
                cert.setRevoked(true);
                // Detach certificate from entity
                cert.setVessel(null);
            }
        }
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

    public String getVesselOrgId() {
        return vesselOrgId;
    }

    public void setVesselOrgId(String vesselOrgId) {
        this.vesselOrgId = vesselOrgId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<VesselAttribute> getAttributes() {
        return attributes;
    }

    public List<Certificate> getCertificates() {
        return certificates;
    }
}
