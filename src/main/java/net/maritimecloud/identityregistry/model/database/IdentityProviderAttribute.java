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
import io.swagger.annotations.ApiModelProperty;
import net.maritimecloud.identityregistry.validators.InPredefinedList;
import org.hibernate.validator.constraints.NotBlank;

import javax.persistence.*;

@Entity
@Table(name = "identity_provider_attributes")
public class IdentityProviderAttribute extends TimestampModel {

    @ApiModelProperty(
            required = true,
            value = "OpenId Connect or SAML2 attribute name",
            allowableValues = "importUrl, validateSignature, signingCertificate, singleLogoutServiceUrl, postBindingResponse, " +
                    "postBindingAuthnRequest, singleSignOnServiceUrl, wantAuthnRequestsSigned, userInfoUrl, validateSignature, " +
                    "tokenUrl, authorizationUrl, logoutUrl, issuer, publicKeySignatureVerifier, clientId, clientSecret"
    )
    @Column(name = "attribute_name")
    @NotBlank
    @InPredefinedList(
            acceptedValues = {"importUrl", "validateSignature", "signingCertificate", "singleLogoutServiceUrl", "postBindingResponse",
                "postBindingAuthnRequest", "singleSignOnServiceUrl", "wantAuthnRequestsSigned", "userInfoUrl", "validateSignature",
                "tokenUrl", "authorizationUrl", "logoutUrl", "issuer", "publicKeySignatureVerifier", "clientId", "clientSecret"}
    )
    private String attributeName;

    @ApiModelProperty(value = "OpenId Connect or SAML2 attribute value", required = true)
    @NotBlank
    @Column(name = "attribute_value")
    private String attributeValue;

    @JsonIgnore
    @ManyToOne
    @JoinColumn(name = "id_organization")
    private Organization organization;

    @Override
    @JsonIgnore
    public Long getId() {
        return id;
    }

    public String getAttributeName() {
        return attributeName;
    }

    public void setAttributeName(String attributeName) {
        this.attributeName = attributeName;
    }

    public String getAttributeValue() {
        return attributeValue;
    }

    public void setAttributeValue(String attributeValue) {
        this.attributeValue = attributeValue;
    }

    public Organization getOrganization() {
        return organization;
    }

    public void setOrganization(Organization organization) {
        this.organization = organization;
    }
}
