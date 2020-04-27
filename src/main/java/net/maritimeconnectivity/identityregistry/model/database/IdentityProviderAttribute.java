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
import io.swagger.annotations.ApiModelProperty;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;
import net.maritimeconnectivity.identityregistry.validators.InPredefinedList;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.validation.constraints.NotBlank;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Entity
@Table(name = "identity_provider_attributes")
@Getter
@Setter
@Accessors(chain = true)
@ToString(exclude = "organization")
public class IdentityProviderAttribute extends TimestampModel {

    @ApiModelProperty(
            required = true,
            value = "OpenId Connect or SAML2 attribute name",
            allowableValues = "importUrl, validateSignature, signingCertificate, singleLogoutServiceUrl, postBindingResponse, " +
                    "postBindingAuthnRequest, singleSignOnServiceUrl, wantAuthnRequestsSigned, userInfoUrl, " +
                    "tokenUrl, authorizationUrl, logoutUrl, issuer, publicKeySignatureVerifier, clientId, clientSecret," +
                    "providerType, firstNameAttr, lastNameAttr, emailAttr, usernameAttr, permissionsAttr"
    )
    @Column(name = "attribute_name", nullable = false)
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
    @Column(name = "attribute_value", nullable = false)
    private String attributeValue;

    @JsonIgnore
    @ManyToOne
    @JoinColumn(name = "id_organization", nullable = false)
    private Organization organization;

    @Override
    @JsonIgnore
    public Long getId() {
        return id;
    }

    /**
     * Compares this IdentityProviderAttribute with another, but only compares AttributeName and AttributeValue
     * @param other The other IdentityProviderAttribute to compare with
     * @return 0 if equal, otherwise non-zero values.
     */
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
        if (this.getAttributeName() != null && !this.getAttributeName().equals(other.getAttributeName())) {
            ret = 1;
        }
        // Check attributeValue content
        if (this.getAttributeValue() != null && !this.getAttributeValue().equals(other.getAttributeValue())) {
            ret = 1;
        }
        return ret;
    }

    /**
     * Compares two IdentityProviderAttribute lists, but only looks the AttributeName and AttributeValue attributes
     * on list elements.
     * @param first First list of IdentityProviderAttribute to compare
     * @param second Second list of IdentityProviderAttribute to compare
     * @return true if lists are equal, else false
     */
    public static boolean listsEquals(Set<IdentityProviderAttribute> first, Set<IdentityProviderAttribute> second) {
        if (first == null && second == null) {
            return true;
        }

        if (first == null || second == null) {
            return false;
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
        return secondCopy.isEmpty();
    }
}
