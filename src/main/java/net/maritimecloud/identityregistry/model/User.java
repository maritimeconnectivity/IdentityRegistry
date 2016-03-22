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
package net.maritimecloud.identityregistry.model;

import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.List;
import java.util.Objects;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.OneToMany;
import javax.persistence.PostPersist;
import javax.persistence.PostUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.hibernate.annotations.Where;

/**
 * Model object representing an user
 */

@Entity
@Table(name = "users")
public class User extends TimestampModel {

    public User() {
    }

    @JsonIgnore
    @Column(name = "id_organization")
    private Long idOrganization;

    @Column(name = "user_org_id")
    private String userOrgId;

    @Column(name = "first_name")
    private String firstName;

    @Column(name = "last_name")
    private String lastName;

    @Column(name = "email")
    private String email;

    @Column(name = "permissions")
    private String permissions;

    @OneToMany(cascade = CascadeType.ALL, mappedBy = "user")
    @Where(clause="revoked != 1 AND CURDATE() BETWEEN start AND end")
    private List<Certificate> certificates;

    // Only used when a user is first created to return a password.
    @Transient
    private String password;

    /** Copies this user into the other */
    public User copyTo(User user) {
        Objects.requireNonNull(user);
        user.setId(id);
        user.setIdOrganization(idOrganization);
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setUserOrgId(userOrgId);
        user.setPermissions(permissions);
        user.getCertificates().clear();
        user.getCertificates().addAll(certificates);
        user.setChildIds();
        return user;
    }

    /** Copies this user into the other
     * Only update things that are allowed to change on update */
    public User selectiveCopyTo(User user) {
        Objects.requireNonNull(user);
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setPermissions(permissions);
        user.setChildIds();
        return user;
    }

    @PostPersist
    @PostUpdate
    void setChildIds() {
        if (this.certificates != null) {
            for (Certificate cert : this.certificates) {
                cert.setUser(this);
            }
        }
    }
    /******************************/
    /** Getters and setters      **/
    /******************************/
    public Long getIdOrganization() {
        return idOrganization;
    }

    public void setIdOrganization(Long idOrganization) {
        this.idOrganization = idOrganization;
    }

    public String getUserOrgId() {
        return userOrgId;
    }

    public void setUserOrgId(String userOrgId) {
        this.userOrgId = userOrgId;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPermissions() {
        return permissions;
    }

    public void setPermissions(String permissions) {
        this.permissions = permissions;
    }

    public List<Certificate> getCertificates() {
        return certificates;
    }

    // Only used when a user is first created to return a password.
    public String getPassword() {
        return password;
    }

    // Only used when a user is first created to return a password.
    public void setPassword(String password) {
        this.password = password;
    }

}

