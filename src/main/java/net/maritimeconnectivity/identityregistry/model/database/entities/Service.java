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
package net.maritimeconnectivity.identityregistry.model.database.entities;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import net.maritimeconnectivity.identityregistry.model.database.Certificate;
import net.maritimeconnectivity.identityregistry.validators.InPredefinedList;

import java.util.Set;

import static io.swagger.v3.oas.annotations.media.Schema.AccessMode.READ_ONLY;

/**
 * Model object representing a service
 */

@Entity
@Table(name = "services")
@Getter
@Setter
@ToString
@NoArgsConstructor
@Schema(description = "Model object representing a service")
public class Service extends NonHumanEntityModel {

    @Schema(description = "Access type of the OpenId Connect client", allowableValues = "public, bearer-only, confidential")
    @Column(name = "oidc_access_type")
    @InPredefinedList(acceptedValues = {"public", "bearer-only", "confidential"})
    private String oidcAccessType;

    @Schema(description = "The client id of the service in MCP. Will be generated.", accessMode = READ_ONLY)
    @Column(name = "oidc_client_id")
    private String oidcClientId;

    @Schema(description = "The client secret of the service in MCP. Will be generated.", accessMode = READ_ONLY)
    @Column(name = "oidc_client_secret")
    private String oidcClientSecret;

    @Schema(description = "The OpenId Connect redirect URI of service.")
    @Column(name = "oidc_redirect_uri")
    private String oidcRedirectUri;

    @Schema(description = "The domain name the service will be available on. Used in the issued certificates for the service.")
    @Column(name = "cert_domain_name")
    private String certDomainName;

    @Schema(description = "DEPRECATED: The version of the service should no longer be set separately from the MRN, " +
            "but should instead be appended to the MRN, if needed. This change has been made to ensure uniqueness of MRNs. " +
            "Note that if you do set a value for this field when you create a new service, the current behavior is " +
            "that it will be appended to the MRN as an additional namespace.", deprecated = true)
    @Deprecated(forRemoval = true)
    private String instanceVersion;

    @Schema(description = "The set of certificates of the service. Cannot be created/updated by editing in the model. Use the dedicated create and revoke calls.", accessMode = READ_ONLY)
    @OneToMany(fetch = FetchType.EAGER, mappedBy = "service")
    private Set<Certificate> certificates;

    @Schema(description = "The vessel that is linked to this service.")
    @ManyToOne
    @JoinColumn(name = "id_vessel")
    private Vessel vessel;

    /**
     * Copies this service into the other
     */
    @Override
    public Service copyTo(EntityModel target) {
        Service service = (Service) super.copyTo(target);
        service.setOidcAccessType(oidcAccessType);
        service.setOidcClientId(oidcClientId);
        service.setOidcClientSecret(oidcClientSecret);
        service.setOidcRedirectUri(oidcRedirectUri);
        service.setCertDomainName(certDomainName);
        service.getCertificates().clear();
        service.getCertificates().addAll(certificates);
        service.setVessel(vessel);
        service.setChildIds();
        return service;
    }

    /**
     * Copies this service into the other
     * Only update things that are allowed to change on update
     */
    @Override
    public Service selectiveCopyTo(EntityModel target) {
        Service service = (Service) super.selectiveCopyTo(target);
        service.setOidcAccessType(oidcAccessType);
        service.setOidcRedirectUri(oidcRedirectUri);
        service.setCertDomainName(certDomainName);
        service.setVessel(vessel);
        service.setChildIds();
        return service;
    }

    public void assignToCert(Certificate cert) {
        cert.setService(this);
    }

    @Override
    public boolean hasSensitiveFields() {
        return true;
    }

    @Override
    public void clearSensitiveFields() {
        this.setOidcAccessType(null);
        this.setOidcClientId(null);
        this.setOidcClientSecret(null);
        this.setOidcRedirectUri(null);
    }

    /**
     * Generates the oidcClientId. Currently done by just using the mrn
     */
    public void generateOidcClientId() {
        if (this.getMrn() == null || this.getMrn().trim().isEmpty()) {
            throw new IllegalArgumentException("Service MRN is empty!");
        }
        this.setOidcClientId(this.getMrn());
    }
}

