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
package net.maritimecloud.identityregistry.model.database;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.annotations.ApiModelProperty;
import net.maritimecloud.identityregistry.validators.MRN;
import org.hibernate.validator.constraints.Email;
import org.hibernate.validator.constraints.Length;
import org.hibernate.validator.constraints.NotBlank;
import org.hibernate.validator.constraints.URL;


import java.util.ArrayList;
import java.util.List;

import javax.persistence.*;
import javax.validation.Valid;

/**
 * Model object representing an organization
 */

@Entity
@Table(name = "organizations")
public class Organization extends CertificateModel {

    @ApiModelProperty(value = "The name of the organization", required = true)
    @Column(name = "name")
    @NotBlank
    private String name;

    // Due to limitation in the X509, Organization MRN must not be longer than 64 characters
    @Length(max = 64)
    @NotBlank
    @MRN
    @ApiModelProperty(value = "The Maritime Resource Name", required = true, readOnly = true)
    @Column(name = "mrn")
    private String mrn;

    @Column(name = "email")
    @Email
    @ApiModelProperty(required = true)
    private String email;

    @Column(name = "url")
    @ApiModelProperty(required = true)
    @NotBlank
    @URL
    private String url;

    @Column(name = "address")
    @NotBlank
    @ApiModelProperty(required = true)
    private String address;

    @Column(name = "country")
    @NotBlank
    @ApiModelProperty(required = true)
    private String country;

    @JsonIgnore
    @Column(name = "type")
    private String type;

    @JsonIgnore
    @Column(name = "approved")
    private boolean approved;

    @Column(name = "federation_type")
    @ApiModelProperty(value = "Type of identity federation used by organization", allowableValues = "test-idp, own-idp, external-idp", readOnly = true)
    private String federationType;

    @JsonIgnore
    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name="id_logo")
    private Logo logo;

    @ApiModelProperty(value = "Cannot be created/updated by editing in the model. Use the dedicate create and revoke calls.")
    @OneToMany(mappedBy = "organization")
    //@Where(clause="UTC_TIMESTAMP() BETWEEN start AND end")
    private List<Certificate> certificates;

    @Valid
    @OneToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL, mappedBy = "organization", orphanRemoval=true)
    private List<IdentityProviderAttribute> identityProviderAttributes;

    public Organization() {
    }

    /** Copies this organization into the other */
    public Organization copyTo(Organization org) {
        org.setName(name);
        org.setEmail(email);
        org.setUrl(url);
        org.setAddress(address);
        org.setCountry(country);
        org.setLogo(logo);
        org.setFederationType(federationType);
        org.setApproved(approved);
        org.getCertificates().clear();
        org.getCertificates().addAll(certificates);
        org.getIdentityProviderAttributes().clear();
        org.getIdentityProviderAttributes().addAll(identityProviderAttributes);
        org.setChildIds();
        return org;
    }

    /** Copies this organization into the other.
     * Skips certificates, approved, logo and shortname */
    public Organization selectiveCopyTo(Organization org) {
        org.setName(name);
        org.setEmail(email);
        org.setUrl(url);
        org.setAddress(address);
        org.setCountry(country);
        org.getIdentityProviderAttributes().clear();
        org.getIdentityProviderAttributes().addAll(identityProviderAttributes);
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
        this.identityProviderAttributes.clear();
        this.federationType = null;
    }

    /******************************/
    /** Getters and setters      **/
    /******************************/
    public String getMrn() {
        return mrn;
    }

    public void setMrn(String mrn) {
        this.mrn = mrn;
    }

    public String getFederationType() {
        return federationType;
    }

    public void setFederationType(String federationType) {
        this.type = federationType;
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

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
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

    public List<IdentityProviderAttribute> getIdentityProviderAttributes() {
        return identityProviderAttributes;
    }

    public void setIdentityProviderAttributes(List<IdentityProviderAttribute> identityProviderAttributes) {
        this.identityProviderAttributes = identityProviderAttributes;
    }

    public Logo getLogo() {
        return logo;
    }

    public void setLogo(Logo logo) {
        this.logo = logo;
    }
}