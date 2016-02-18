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

import java.util.List;
import java.util.Objects;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.PostPersist;
import javax.persistence.PostUpdate;
import javax.persistence.Table;

import org.hibernate.annotations.Where;

/**
 * Model object representing an organization
 */

@Entity
@Table(name = "vessels")
public class Vessel extends TimestampModel {

    public Vessel() {
    }

    @JsonIgnore
    @Column(name = "id_organization")
    private int idOrganization;

    @Column(name = "vessel_org_id")
    private String vesselOrgId;

    @Column(name = "name")
    private String name;

    @OneToMany(cascade = CascadeType.ALL, mappedBy = "vessel")
    private List<VesselAttribute> attributes;

    @OneToMany(cascade = CascadeType.ALL, mappedBy = "vessel")
    @Where(clause="revoked != 1 AND CURDATE() BETWEEN start AND end")
    private List<Certificate> certificates;

    /*
    @ManyToOne
    @JoinColumn(name="id_organization")
    private Organization organization;*/

    /** Copies this vessel into the other */
    public Vessel copyTo(Vessel vessel) {
        Objects.requireNonNull(vessel);
        vessel.setId(id);
        vessel.setIdOrganization(idOrganization);
        vessel.setName(name);
        vessel.setVesselOrgId(vesselOrgId);
        vessel.setAttributes(attributes);
        vessel.setCertificate(certificates);
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
    /******************************/
    /** Getters and setters      **/
    /******************************/
    public int getIdOrganization() {
        return idOrganization;
    }

    public void setIdOrganization(int idOrganization) {
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

    public void setAttributes(List<VesselAttribute> attributes) {
        this.attributes = attributes;
    }

    public List<Certificate> getCertificates() {
        return certificates;
    }

    @JsonIgnore
    public void setCertificate(List<Certificate> certificates) {
        this.certificates = certificates;
    }

    /*
    public Organization getOrganization() {
        return organization;
    }

    public void setOrganization(Organization organization) {
        this.organization = organization;
    }*/
}
