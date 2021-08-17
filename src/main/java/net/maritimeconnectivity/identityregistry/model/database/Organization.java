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
package net.maritimeconnectivity.identityregistry.model.database;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import net.maritimeconnectivity.identityregistry.validators.MCPMRN;
import net.maritimeconnectivity.identityregistry.validators.MRN;
import org.hibernate.validator.constraints.Length;
import org.hibernate.validator.constraints.URL;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.PostPersist;
import javax.persistence.Table;
import javax.validation.Valid;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import java.util.Set;

import static io.swagger.v3.oas.annotations.media.Schema.AccessMode.READ_ONLY;

/**
 * Model object representing an organization
 */

@Entity
@Table(name = "organizations")
@Getter
@Setter
@ToString
@NoArgsConstructor
public class Organization extends CertificateModel {

    @Schema(description = "The name of the organization", required = true)
    @Column(name = "name", nullable = false)
    @NotBlank
    private String name;

    // Due to limitation in the X509, Organization MRN must not be longer than 64 characters
    @Length(max = 64)
    @NotBlank
    @MCPMRN
    @Schema(description = "Maritime Connectivity Platform Maritime Resource Name", required = true)
    @Column(name = "mrn", nullable = false)
    private String mrn;

    @MRN
    @Schema(description = "Subsidiary Maritime Resource Name")
    @Column(name = "mrn_subsidiary")
    private String mrnSubsidiary;

    @Schema(description = "URL of MMS that the identity is registered")
    @Column(name = "home_mms_url")
    private String homeMMSUrl;

    @Column(name = "email", nullable = false)
    @Email
    @Schema(required = true)
    private String email;

    @Column(name = "url", nullable = false)
    @Schema(required = true)
    @NotBlank
    @URL
    private String url;

    @Column(name = "address", nullable = false)
    @NotBlank
    @Schema(required = true)
    private String address;

    @Column(name = "country")
    @NotBlank
    @Schema(required = true)
    private String country;

    @JsonIgnore
    @Column(name = "approved", nullable = false)
    private boolean approved;

    @Column(name = "federation_type", nullable = false)
    @Schema(description = "Type of identity federation used by organization", allowableValues = "test-idp, own-idp, external-idp", accessMode = READ_ONLY)
    private String federationType;

    @JsonIgnore
    @OneToOne(cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name="id_logo")
    private Logo logo;

    @Schema(description = "Cannot be created/updated by editing in the model. Use the dedicate create and revoke calls.")
    @OneToMany(fetch = FetchType.EAGER, mappedBy = "organization")
    private Set<Certificate> certificates;

    @Valid
    @OneToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL, mappedBy = "organization", orphanRemoval=true)
    private Set<IdentityProviderAttribute> identityProviderAttributes;

    @JsonIgnore
    @Column(name = "certificate_authority", nullable = false)
    private String certificateAuthority;

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
        org.setMrnSubsidiary(mrnSubsidiary);
        org.setHomeMMSUrl(homeMMSUrl);
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
        org.setMrnSubsidiary(mrnSubsidiary);
        org.setHomeMMSUrl(homeMMSUrl);
        org.getIdentityProviderAttributes().clear();
        org.getIdentityProviderAttributes().addAll(identityProviderAttributes);
        org.setChildIds();
        return org;
    }

    @Override
    @PostPersist
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
