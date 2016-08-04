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
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Objects;

import javax.persistence.*;

/**
 * Model object representing an organization
 */

@Entity
@Table(name = "organizations")
public class Organization extends CertificateModel {

    @Column(name = "name")
    private String name;

    @Column(name = "short_name")
    private String shortName;

    @Column(name = "email")
    private String email;

    @Column(name = "url")
    private String url;

    @Column(name = "address")
    private String address;

    @Column(name = "country")
    private String country;

    @Column(name = "type")
    private String type;

    // Only used when a organization is first created to return a password.
    @Transient
    private String password;

    @JsonIgnore
    @Column(name = "approved")
    private boolean approved;

    @JsonIgnore
    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name="id_logo")
    private Logo logo;

    @OneToMany(mappedBy = "organization")
    //@Where(clause="UTC_TIMESTAMP() BETWEEN start AND end")
    private List<Certificate> certificates;

    @OneToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL, mappedBy = "organization", orphanRemoval=true)
    private List<IdentityProviderAttribute> identityProviderAttributes;

    public Organization() {
    }

    /** Copies this organization into the other */
    public Organization copyTo(Organization org) {
        Objects.requireNonNull(org);
        org.setName(name);
        org.setShortName(shortName);
        org.setEmail(email);
        org.setUrl(url);
        org.setAddress(address);
        org.setCountry(country);
        org.setLogo(logo);
        org.setType(type);
        org.setApproved(approved);
        org.setCertificates(certificates);
        org.setIdentityProviderAttributes(identityProviderAttributes);
        org.setChildIds();
        return org;
    }

    /** Copies this organization into the other.
     * Skips certificates, approved, logo and shortname */
    public Organization selectiveCopyTo(Organization org) {
        Objects.requireNonNull(org);
        org.setName(name);
        org.setEmail(email);
        org.setUrl(url);
        org.setAddress(address);
        org.setCountry(country);
        org.setType(type);
        org.setIdentityProviderAttributes(identityProviderAttributes);
        org.setChildIds();
        return org;
    }

    @PostPersist
    @PostUpdate
    public void setChildIds() {
        super.setChildIds();
        if (this.identityProviderAttributes != null) {
            for (IdentityProviderAttribute attr : this.identityProviderAttributes) {
                attr.setOrganization(this);
            }
        }
    }

    public void assignToCert(Certificate cert){
        cert.setOrganization(this);
    }


    /** Creates a copy of this organization */
    public Organization copy() {
        return copyTo(new Organization());
    }

    @Override
    public boolean hasSensitiveFields() {
        return true;
    }

    @Override
    public void clearSensitiveFields() {
        this.identityProviderAttributes = null;
    }

    /******************************/
    /** Getters and setters      **/
    /******************************/
    @JsonIgnore
    @Override
    public Long getId() {
        return id;
    }

    @JsonIgnore
    @Override
    protected void setId(Long id) {
        this.id = id;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String getShortName() {
        return shortName;
    }

    public void setShortName(String shortName) {
        this.shortName = shortName;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    // Only used when a organization is first created to return a password.
    public String getPassword() {
        return password;
    }

    // Only used when a organization is first created to return a password.
    public void setPassword(String password) {
        this.password = password;
    }

    public boolean getApproved() {
        return approved;
    }

    public void setApproved(boolean approved) {
        this.approved = approved;
    }

    public List<Certificate> getCertificates() {
        return certificates;
    }

    public void setCertificates(List<Certificate> certificates) {
        this.certificates.clear();
        this.certificates.addAll(certificates);
    }

    public List<IdentityProviderAttribute> getIdentityProviderAttributes() {
        return identityProviderAttributes;
    }

    public void setIdentityProviderAttributes(List<IdentityProviderAttribute> identityProviderAttributes) {
        this.identityProviderAttributes.clear();
        this.identityProviderAttributes.addAll(identityProviderAttributes);
    }

    public Logo getLogo() {
        return logo;
    }

    public void setLogo(Logo logo) {
        this.logo = logo;
    }
}