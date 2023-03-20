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

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.PostPersist;
import jakarta.persistence.Table;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import java.util.Set;

import static io.swagger.v3.oas.annotations.media.Schema.AccessMode.READ_ONLY;
import static io.swagger.v3.oas.annotations.media.Schema.AccessMode.WRITE_ONLY;

/**
 * Model object representing an organization
 */
@Entity
@Table(name = "organizations")
@Getter
@Setter
@ToString
@NoArgsConstructor
@Schema(description = "Model object representing an organization")
public class Organization extends CertificateModel {

    @Schema(description = "The name of the organization", requiredMode = Schema.RequiredMode.REQUIRED)
    @Column(name = "name", nullable = false)
    @NotBlank
    private String name;

    // Due to limitation in the X509, Organization MRN must not be longer than 64 characters
    @Length(max = 64)
    @NotBlank
    @MCPMRN
    @Schema(description = "Maritime Connectivity Platform Maritime Resource Name", requiredMode = Schema.RequiredMode.REQUIRED)
    @Column(name = "mrn", nullable = false)
    private String mrn;

    @MRN
    @Schema(description = "Subsidiary Maritime Resource Name")
    @Column(name = "mrn_subsidiary")
    private String mrnSubsidiary;

    @Schema(description = "URL of the MMS that the organization is registered with")
    @Column(name = "home_mms_url")
    private String homeMMSUrl;

    @Column(name = "email", nullable = false)
    @NotBlank
    @Email
    @Schema(description = "The email of the organization", requiredMode = Schema.RequiredMode.REQUIRED)
    private String email;

    @Column(name = "url", nullable = false)
    @Schema(description = "The URL of the organization's website", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    @URL
    private String url;

    @Column(name = "address", nullable = false)
    @NotBlank
    @Schema(description = "The address of the organization", requiredMode = Schema.RequiredMode.REQUIRED)
    private String address;

    @Column(name = "country")
    @NotBlank
    @Schema(description = "The country that the organization is located in", requiredMode = Schema.RequiredMode.REQUIRED)
    private String country;

    @JsonIgnore
    @Column(name = "approved", nullable = false)
    private boolean approved;

    @Column(name = "federation_type", nullable = false)
    @Schema(description = "Type of identity federation used by organization", allowableValues = {"test-idp", "own-idp", "external-idp"})
    private String federationType;

    @JsonIgnore
    @OneToOne(cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name = "id_logo")
    private Logo logo;

    @Schema(description = "The set of certificates of the organization. Cannot be created/updated by editing in the model. Use the dedicate create and revoke calls.", accessMode = READ_ONLY)
    @OneToMany(fetch = FetchType.EAGER, mappedBy = "organization")
    private Set<Certificate> certificates;

    @Valid
    @OneToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL, mappedBy = "organization", orphanRemoval = true)
    @Schema(description = "The identity provider attributes of the organization", accessMode = WRITE_ONLY)
    private Set<IdentityProviderAttribute> identityProviderAttributes;

    @JsonIgnore
    @Column(name = "certificate_authority", nullable = false)
    @Schema(description = "The name of the CA of the organization", accessMode = READ_ONLY)
    private String certificateAuthority;

    /**
     * Copies this organization into the other
     */
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

    /**
     * Copies this organization into the other.
     * Skips certificates, approved, logo and shortname
     */
    public Organization selectiveCopyTo(Organization org) {
        org.setName(name);
        org.setEmail(email);
        org.setUrl(url);
        org.setAddress(address);
        org.setCountry(country);
        org.setMrnSubsidiary(mrnSubsidiary);
        org.setHomeMMSUrl(homeMMSUrl);
        if (identityProviderAttributes != null) {
            org.getIdentityProviderAttributes().clear();
            org.getIdentityProviderAttributes().addAll(identityProviderAttributes);
        }
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

    public void assignToCert(Certificate cert) {
        cert.setOrganization(this);
    }


    /**
     * Creates a copy of this organization
     */
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
