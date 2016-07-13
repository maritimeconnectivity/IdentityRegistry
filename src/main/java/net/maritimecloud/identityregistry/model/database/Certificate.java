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
package net.maritimecloud.identityregistry.model.database;

import com.fasterxml.jackson.annotation.JsonIgnore;
import net.maritimecloud.identityregistry.model.database.Organization;
import net.maritimecloud.identityregistry.model.database.TimestampModel;
import net.maritimecloud.identityregistry.model.database.entities.Device;
import net.maritimecloud.identityregistry.model.database.entities.Service;
import net.maritimecloud.identityregistry.model.database.entities.User;
import net.maritimecloud.identityregistry.model.database.entities.Vessel;

import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

/**
 * Model object representing a certificate
 */

@Entity
@Table(name="certificates")
public class Certificate extends TimestampModel {

    public Certificate() {
    }

    @Column(name = "certificate", columnDefinition = "MEDIUMTEXT")
    private String certificate;

    @Column(name = "start")
    private Date start;

    @Column(name = "end")
    private Date end;

    @Column(name = "revoked")
    private boolean revoked;

    @Column(name= "revoked_at")
    private Date revokedAt;

    /* Can contain values as in rfc5280:
        unspecified (0)
        keyCompromise (1)
        CACompromise (2)
        affiliationChanged (3)
        superseded (4)
        cessationOfOperation (5)
        certificateHold (6)
        removeFromCRL (8)
        privilegeWithdrawn (9)
        AACompromise (10)
       We only store the text value, in lowercase. */
    @Column(name = "revoke_reason")
    private String revokeReason;

    @JsonIgnore
    @ManyToOne
    @JoinColumn(name = "id_vessel")
    private Vessel vessel;

    @JsonIgnore
    @ManyToOne
    @JoinColumn(name = "id_user")
    private User user;

    @JsonIgnore
    @ManyToOne
    @JoinColumn(name = "id_device")
    private Device device;

    @JsonIgnore
    @ManyToOne
    @JoinColumn(name = "id_service")
    private Service service;

    @JsonIgnore
    @ManyToOne
    @JoinColumn(name = "id_organization")
    private Organization organization;

    /******************************/
    /** Getters and setters      **/
    /******************************/

    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    public Date getStart() {
        return start;
    }

    public void setStart(Date start) {
        this.start = start;
    }

    public Date getEnd() {
        return end;
    }

    public void setEnd(Date end) {
        this.end = end;
    }

    public boolean getRevoked() {
        return revoked;
    }

    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }

    public Date getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(Date revokedAt) {
        this.revokedAt = revokedAt;
    }

    public String getRevokeReason() {
        return revokeReason;
    }

    public void setRevokeReason(String revokeReason) {
        this.revokeReason = revokeReason;
    }

    public Vessel getVessel() {
        return vessel;
    }

    public void setVessel(Vessel vessel) {
        this.vessel = vessel;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Device getDevice() {
        return device;
    }

    public void setDevice(Device device) {
        this.device = device;
    }

    public Service getService() {
        return service;
    }

    public void setService(Service service) {
        this.service = service;
    }

    public Organization getOrganization() {
        return organization;
    }

    public void setOrganization(Organization organization) {
        this.organization = organization;
    }

}