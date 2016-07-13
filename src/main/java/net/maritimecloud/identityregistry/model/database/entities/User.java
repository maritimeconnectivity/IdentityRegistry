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
package net.maritimecloud.identityregistry.model.database.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;

import io.swagger.annotations.ApiModelProperty;

import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.Transient;

import net.maritimecloud.identityregistry.model.database.Certificate;

/**
 * Model object representing an user
 */

@Entity
@Table(name = "users")
public class User extends EntityModel {

    public User() {
    }

    @ApiModelProperty(required = true)
    @Column(name = "user_org_id")
    private String userOrgId;

    @Column(name = "first_name")
    private String firstName;

    @Column(name = "last_name")
    private String lastName;

    @Column(name = "email")
    private String email;

    @OneToMany(mappedBy = "user")
    //@Where(clause="UTC_TIMESTAMP() BETWEEN start AND end")
    private List<Certificate> certificates;

    // Only used when a user is first created to return a password.
    @Transient
    private String password;

    /** Copies this user into the other */
    public User copyTo(User user) {
        user = (User) super.copyTo(user);
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setUserOrgId(userOrgId);
        user.getCertificates().clear();
        user.getCertificates().addAll(certificates);
        user.setChildIds();
        return user;
    }

    /** Copies this user into the other
     * Only update things that are allowed to change on update */
    public User selectiveCopyTo(User user) {
        user = (User) super.selectiveCopyTo(user);
        user.setEmail(email);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setChildIds();
        return user;
    }

    protected void assignToCert(Certificate cert){
        cert.setUser(this);
    }

    /******************************/
    /** Getters and setters      **/
    /******************************/
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

