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
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import net.maritimeconnectivity.identityregistry.model.database.Certificate;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.pki.PKIIdentity;
import org.bouncycastle.asn1.x500.X500Name;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import java.util.Locale;
import java.util.Set;

import static io.swagger.v3.oas.annotations.media.Schema.AccessMode.READ_ONLY;
import static net.maritimeconnectivity.pki.CertificateBuilder.escapeSpecialCharacters;

/**
 * Model object representing a user
 */

@Entity
@Table(name = "users")
@Getter
@Setter
@ToString(exclude = "certificates")
@NoArgsConstructor
@Schema(description = "Model object representing a user")
public class User extends EntityModel {

    @Schema(description = "The first name of the user", required = true)
    @NotBlank
    @Column(name = "first_name")
    private String firstName;

    @Schema(description = "The last name of the user", required = true)
    @NotBlank
    @Column(name = "last_name")
    private String lastName;

    @Schema(description = "The email of the user", required = true)
    @NotBlank
    @Email
    @Column(name = "email")
    private String email;

    @Schema(description = "The set of certificates of the user. Cannot be created/updated by editing in the model. Use the dedicated create and revoke calls.", accessMode = READ_ONLY)
    @OneToMany(fetch = FetchType.EAGER, mappedBy = "user")
    private Set<Certificate> certificates;

    /** Copies this user into the other */
    @Override
    public User copyTo(EntityModel target) {
        User user = (User) super.copyTo(target);
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.getCertificates().clear();
        user.getCertificates().addAll(certificates);
        user.setChildIds();
        return user;
    }

    /** Copies this user into the other
     * Only update things that are allowed to change on update */
    @Override
    public User selectiveCopyTo(EntityModel target) {
        User user = (User) super.selectiveCopyTo(target);
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setChildIds();
        return user;
    }

    public void assignToCert(Certificate cert){
        cert.setUser(this);
    }

    public PKIIdentity toPkiIdentity(Organization organization) {
        PKIIdentity pkiIdentity = new PKIIdentity();
        pkiIdentity.setMrn(getMrn());
        pkiIdentity.setPermissions(getPermissions());
        pkiIdentity.setDn(constructDN(organization));
        pkiIdentity.setMrnSubsidiary(getMrnSubsidiary());
        pkiIdentity.setHomeMmsUrl(getHomeMMSUrl());

        return pkiIdentity;
    }

    public String constructDN(Organization organization) {
        // Try to find the correct country code, else we just use the country name as code
        String orgCountryCode = organization.getCountry();
        String[] locales = Locale.getISOCountries();
        for (String countryCode : locales) {
            Locale loc = new Locale("", countryCode);
            if (loc.getDisplayCountry(Locale.ENGLISH).equals(orgCountryCode)) {
                orgCountryCode = loc.getCountry();
                break;
            }
        }
        String fullName = firstName + " " + lastName;
        String dn = String.format("C=%s, O=%s, OU=user, CN=%s, UID=%s, E=%s", escapeSpecialCharacters(orgCountryCode), escapeSpecialCharacters(organization.getMrn()),
                escapeSpecialCharacters(fullName), escapeSpecialCharacters(getMrn()), escapeSpecialCharacters(getEmail()));
        // Make sure to print out DN correctly. Don't know if we actually need to do this as it seems quite redundant
        X500Name x500DN = new X500Name(dn);
        return x500DN.toString();
    }
}

