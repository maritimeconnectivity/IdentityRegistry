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
package net.maritimecloud.identityregistry.model.database.entities;

import io.swagger.annotations.ApiModelProperty;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import net.maritimecloud.identityregistry.model.database.Certificate;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import java.util.Set;

/**
 * Model object representing an user
 */

@Entity
@Table(name = "users")
@Getter
@Setter
@ToString(exclude = "certificates")
public class User extends EntityModel {

    public User() {
    }

    @ApiModelProperty(required = true)
    @NotBlank
    @Column(name = "first_name")
    private String firstName;

    @ApiModelProperty(required = true)
    @NotBlank
    @Column(name = "last_name")
    private String lastName;

    @ApiModelProperty(required = true)
    @NotBlank
    @Email
    @Column(name = "email")
    private String email;

    @ApiModelProperty(value = "Cannot be created/updated by editing in the model. Use the dedicate create and revoke calls.")
    @OneToMany(fetch = FetchType.EAGER, mappedBy = "user")
    private Set<Certificate> certificates;

    /** Copies this user into the other */
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
}

