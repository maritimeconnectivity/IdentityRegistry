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
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import net.maritimecloud.identityregistry.validators.MRN;
import org.hibernate.validator.constraints.Email;
import org.hibernate.validator.constraints.Length;
import org.hibernate.validator.constraints.NotBlank;
import org.hibernate.validator.constraints.URL;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.PostPersist;
import javax.persistence.PostUpdate;
import javax.persistence.Table;
import javax.validation.Valid;
import java.util.List;

/**
 * Model object representing an organization
 */

@Entity
@Table(name = "organizations")
@Getter
@Setter
@ToString
public class Organization extends CertificateModel {

    @ApiModelProperty(value = "The name of the organization", required = true)
    @Column(name = "name", nullable = false)
    @NotBlank
    private String name;

    // Due to limitation in the X509, Organization MRN must not be longer than 64 characters
    @Length(max = 64)
    @NotBlank
    @MRN
    @ApiModelProperty(value = "The Maritime Resource Name", required = true, readOnly = true)
    @Column(name = "mrn", nullable = false)
    private String mrn;

    @Column(name = "email", nullable = false)
    @Email
    @ApiModelProperty(required = true)
    private String email;

    @Column(name = "url", nullable = false)
    @ApiModelProperty(required = true)
    @NotBlank
    @URL
    private String url;

    @Column(name = "address", nullable = false)
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
    @Column(name = "approved", nullable = false)
    private boolean approved;

    @Column(name = "federation_type", nullable = false)
    @ApiModelProperty(value = "Type of identity federation used by organization", allowableValues = "test-idp, own-idp, external-idp", readOnly = true)
    private String federationType;

    @JsonIgnore
    @OneToOne(cascade = CascadeType.ALL, orphanRemoval = true)
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
}