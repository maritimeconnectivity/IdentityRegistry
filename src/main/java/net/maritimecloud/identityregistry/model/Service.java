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

import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Objects;

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
 * Model object representing a service
 */

@Entity
@Table(name = "services")
public class Service extends TimestampModel {

    public Service() {
    }

    @Column(name = "id_organization")
    private Long idOrganization;

    @Column(name = "service_org_id")
    private String serviceOrgId;

    @Column(name = "name")
    private String name;

    @Column(name = "mrn")
    private String mrn;

    @Column(name = "permissions")
    private String permissions;

    @OneToMany(mappedBy = "service")
    //@Where(clause="UTC_TIMESTAMP() BETWEEN start AND end")
    private List<Certificate> certificates;

    /** Copies this organization into the other */
    public Service copyTo(Service service) {
        Objects.requireNonNull(service);
        service.setId(id);
        service.setIdOrganization(idOrganization);
        service.setName(name);
        service.setServiceOrgId(serviceOrgId);
        service.setMrn(mrn);
        service.setPermissions(permissions);
        service.getCertificates().clear();
        service.getCertificates().addAll(certificates);
        service.setChildIds();
        return service;
    }

    /** Copies this service into the other
     * Only update things that are allowed to change on update */
    public Service selectiveCopyTo(Service service) {
        service.setName(name);
        service.setServiceOrgId(serviceOrgId);
        service.setMrn(mrn);
        service.setPermissions(permissions);
        service.setChildIds();
        return service;
    }

    @PostPersist
    @PostUpdate
    void setChildIds() {
        if (this.certificates != null) {
            for (Certificate cert : this.certificates) {
                cert.setService(this);
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

    public String getServiceOrgId() {
        return serviceOrgId;
    }

    public void setServiceOrgId(String serviceOrgId) {
        this.serviceOrgId = serviceOrgId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getMrn() {
        return mrn;
    }

    public void setMrn(String mrn) {
        this.mrn = mrn;
    }

    public String getPermissions() {
        return permissions;
    }

    public void setPermissions(String permissions) {
        this.permissions = permissions;
    }

    public List<Certificate> getCertificates() {
        return certificates;
    }
}

