/* Copyright 2015 Danish Maritime Authority.
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

import java.util.Objects;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.OneToMany;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;

/**
 * Model object representing an organization
 */

@Entity
@Table(name = "organizations")
public class Organization extends TimestampModel {

    @Column(name = "name")
    private String name;

    @Column(name = "short_name")
    private String shortName;

    @Column(name = "email")
    private String email;

    @Column(name = "url")
    private String url;

    @Column(name = "address")
    private String address;

    @Column(name = "country")
    private String country;

    @Column(name = "type")
    private String type;

    @Column(name = "oidc_well_known_url")
    private String OIDCWellKnownUrl;

    @JsonIgnore
    @Column(name = "oidc_client_name")
    private String OIDCClientName;

    @JsonIgnore
    @Column(name = "oidc_client_secret")
    private String OIDCClientSecret;

    @JsonIgnore
    @Column(name = "password_hash")
    private String passwordHash;

    // Only used when a organization is first created to return a password.
    @Transient
    private String password;

    @JsonIgnore
    private byte[] logo;

    public Organization() {
    }

    /** Copies this organization into the other */
    public Organization copyTo(Organization org) {
        Objects.requireNonNull(org);
        org.setId(id);
        org.setName(name);
        org.setShortName(shortName);
        org.setEmail(email);
        org.setUrl(url);
        org.setCountry(country);
        org.setLogo(logo);
        org.setType(type);
        return org;
    }

    /** Creates a copy of this organization */
    public Organization copy() {
        return copyTo(new Organization());
    }

    /******************************/
    /** Getters and setters      **/
    /******************************/

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public byte[] getLogo() {
        return logo;
    }

    public void setLogo(byte[] logo) {
        this.logo = logo;
    }

    public String getShortName() {
        return shortName;
    }

    public void setShortName(String shortName) {
        this.shortName = shortName;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    // Only used when a organization is first created to return a password.
    public String getPassword() {
        return password;
    }

 // Only used when a organization is first created to return a password.
    public void setPassword(String password) {
        this.password = password;
    }

    public String getOIDCWellKnownUrl() {
        return OIDCWellKnownUrl;
    }

    public void setOIDCWellKnownUrl(String oIDCWellKnownUrl) {
        this.OIDCWellKnownUrl = oIDCWellKnownUrl;
    }

    public String getOIDCClientName() {
        return OIDCClientName;
    }

    public void setOIDCClientName(String oIDCClientName) {
        OIDCClientName = oIDCClientName;
    }

    public String getOIDCClientSecret() {
        return OIDCClientSecret;
    }

    public void setOIDCClientSecret(String oIDCClientSecret) {
        OIDCClientSecret = oIDCClientSecret;
    }

}