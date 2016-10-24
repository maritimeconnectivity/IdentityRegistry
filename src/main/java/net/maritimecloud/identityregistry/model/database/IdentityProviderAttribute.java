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
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "identity_provider_attributes")
public class IdentityProviderAttribute extends TimestampModel {

    @ApiModelProperty(
            required = true,
            value = "OpenId Connect or SAML2 attribute name",
            allowableValues = "importUrl, validateSignature, signingCertificate, singleLogoutServiceUrl, postBindingResponse, " +
                    "postBindingAuthnRequest, singleSignOnServiceUrl, wantAuthnRequestsSigned, userInfoUrl, " +
                    "tokenUrl, authorizationUrl, logoutUrl, issuer, publicKeySignatureVerifier, clientId, clientSecret," +
                    "providerType, firstNameAttr, lastNameAttr, emailAttr, usernameAttr, permissionsAttr"
    )
    @Column(name = "attribute_name")
    @NotBlank
    @InPredefinedList(
            acceptedValues = {"importUrl", "validateSignature", "signingCertificate", "singleLogoutServiceUrl", "postBindingResponse",
                "postBindingAuthnRequest", "singleSignOnServiceUrl", "wantAuthnRequestsSigned", "userInfoUrl",
                "tokenUrl", "authorizationUrl", "logoutUrl", "issuer", "publicKeySignatureVerifier", "clientId", "clientSecret",
                "providerType", "firstNameAttr", "lastNameAttr", "emailAttr", "usernameAttr", "permissionsAttr"}
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

    public int compareNameAndValueTo(IdentityProviderAttribute other) {
        // Check if "other" is null
        if (other == null) {
            return -1;
        }
        // If all are null they are equal!
        if (this.getAttributeName() == null && other.getAttributeName() == null
                && this.getAttributeValue() == null && other.getAttributeValue() == null) {
            return 0;
        }
        // Check for null values
        if ((this.getAttributeName() != null && other.getAttributeName() == null)
                || (this.getAttributeValue() != null && other.getAttributeValue() == null)) {
            return -1;
        }
        if ((this.getAttributeName() == null && other.getAttributeName() != null)
                || (this.getAttributeValue() == null && other.getAttributeValue() != null)) {
            return 1;
        }
        int ret = 0;
        // Check attributeName content
        if (this.getAttributeName() != null && other.getAttributeName() != null
                && !this.getAttributeName().equals(other.getAttributeName())) {
            ret = 1;
        }
        // Check attributeValue content
        if (this.getAttributeValue() != null && other.getAttributeValue() != null
                && !this.getAttributeValue().equals(other.getAttributeValue())) {
            ret = 1;
        }
        return ret;
    }

    public static boolean listsEquals(List<IdentityProviderAttribute> first, List<IdentityProviderAttribute> second) {
        if (first == null && second != null || first != null && second == null) {
            return false;
        }
        if (first == null && second == null) {
            return true;
        }
        if (first.size() != second.size()) {
            return false;
        }
        List<IdentityProviderAttribute> secondCopy = new ArrayList<>(second);
        for (IdentityProviderAttribute attrInFirst : first) {
            boolean foundMatch = false;
            if (attrInFirst == null) {
                int nullIdx = secondCopy.indexOf(null);
                secondCopy.remove(nullIdx);
                continue;
            }
            for (IdentityProviderAttribute attrInSecond : secondCopy) {
                if (attrInFirst.compareNameAndValueTo(attrInSecond) == 0) {
                    foundMatch = true;
                    secondCopy.remove(attrInSecond);
                    break;
                }
            }
            if (!foundMatch) {
                return false;
            }
        }
        if (secondCopy.size() == 0) {
            return true;
        }
        return false;
    }
}
