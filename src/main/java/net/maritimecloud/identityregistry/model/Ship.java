/* Copyright 2015 Danish Maritime Authority.
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

/**
 * Model object representing an organization
 */

@Entity
@Table(name = "ships")
public class Ship extends TimestampModel {

    public Ship() {
    }

    @JsonIgnore
    @Column(name = "id_organization")
    private int idOrganization;

    @Column(name = "ship_org_id")
    private String shipOrgId;

    @Column(name = "name")
    private String name;

    @OneToMany(cascade = CascadeType.ALL, mappedBy = "ship")
    private List<ShipAttribute> attributes;

    @OneToMany(cascade = CascadeType.ALL, mappedBy = "ship")
    private List<Certificate> certificates;

    /*
    @ManyToOne
    @JoinColumn(name="id_organization")
    private Organization organization;*/

    /** Copies this ship into the other */
    public Ship copyTo(Ship ship) {
        Objects.requireNonNull(ship);
        ship.setId(id);
        ship.setIdOrganization(idOrganization);
        ship.setName(name);
        ship.setShipOrgId(shipOrgId);
        ship.setAttributes(attributes);
        ship.setCertificate(certificates);
        return ship;
    }

    @PostPersist
    @PostUpdate
    void setChildIds() {
        if (this.attributes != null) {
            for (ShipAttribute attr : this.attributes) {
                attr.setShip(this);
            }
        }
        if (this.certificates != null) {
            for (Certificate cert : this.certificates) {
                cert.setShip(this);
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

    public String getShipOrgId() {
        return shipOrgId;
    }

    public void setShipOrgId(String shipOrgId) {
        this.shipOrgId = shipOrgId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<ShipAttribute> getAttributes() {
        return attributes;
    }

    public void setAttributes(List<ShipAttribute> attributes) {
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
