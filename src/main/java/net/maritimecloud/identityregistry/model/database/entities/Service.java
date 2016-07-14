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

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import net.maritimecloud.identityregistry.model.database.Certificate;

/**
 * Model object representing a service
 */

@Entity
@Table(name = "services")
public class Service extends NonHumanEntityModel {

    public Service() {
    }

    @Column(name = "service_org_id")
    private String serviceOrgId;

    @Column(name = "oidc_access_type")
    private String oidcAccessType;

    @Column(name = "oidc_client_id")
    private String oidcClientId;

    @Column(name = "oidc_client_secret")
    private String oidcClientSecret;

    @Column(name = "oidc_redirect_uri")
    private String oidcRedirectUri;

    @OneToMany(mappedBy = "service")
    //@Where(clause="UTC_TIMESTAMP() BETWEEN start AND end")
    private List<Certificate> certificates;

    /** Copies this service into the other */
    public Service copyTo(Service service) {
        service = (Service) super.copyTo(service);
        service.setServiceOrgId(serviceOrgId);
        service.setOidcAccessType(oidcAccessType);
        service.setOidcClientId(oidcClientId);
        service.setOidcClientSecret(oidcClientSecret);
        service.setOidcRedirectUri(oidcRedirectUri);
        service.getCertificates().clear();
        service.getCertificates().addAll(certificates);
        service.setChildIds();
        return service;
    }

    /** Copies this service into the other
     * Only update things that are allowed to change on update */
    public Service selectiveCopyTo(Service service) {
        service = (Service) super.selectiveCopyTo(service);
        service.setServiceOrgId(serviceOrgId);
        service.setOidcAccessType(oidcAccessType);
        service.setOidcRedirectUri(oidcRedirectUri);
        service.setChildIds();
        return service;
    }

    public void assignToCert(Certificate cert){
        cert.setService(this);
    }

    /******************************/
    /** Getters and setters      **/
    /******************************/
    public String getServiceOrgId() {
        return serviceOrgId;
    }

    public void setServiceOrgId(String serviceOrgId) {
        this.serviceOrgId = serviceOrgId;
    }

    public List<Certificate> getCertificates() {
        return certificates;
    }

    public String getOidcAccessType() {
        return oidcAccessType;
    }

    public void setOidcAccessType(String oidcAccessType) {
        this.oidcAccessType = oidcAccessType;
    }

    public String getOidcClientId() {
        return oidcClientId;
    }

    public void setOidcClientId(String oidcClientId) {
        this.oidcClientId = oidcClientId;
    }

    public String getOidcClientSecret() {
        return oidcClientSecret;
    }

    public void setOidcClientSecret(String oidcClientSecret) {
        this.oidcClientSecret = oidcClientSecret;
    }

    public String getOidcRedirectUri() {
        return oidcRedirectUri;
    }

    public void setOidcRedirectUri(String oidcRedirectUri) {
        this.oidcRedirectUri = oidcRedirectUri;
    }
}

