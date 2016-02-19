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
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

import javax.persistence.Column;
import javax.persistence.Entity;
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

    @JsonIgnore
    @Column(name = "oidc_well_known_url")
    private String oidcWellKnownUrl;

    @JsonIgnore
    @Column(name = "oidc_client_name")
    private String oidcClientName;

    @JsonIgnore
    @Column(name = "oidc_client_secret")
    private String oidcClientSecret;

    @JsonIgnore
    @Column(name = "password_hash")
    private String passwordHash;

    // Only used when a organization is first created to return a password.
    @Transient
    private String password;

    @JsonIgnore
    @Column(name = "logo")
    private byte[] logo;

    public Organization() {
    }

    /** Copies this organization into the other */
    public Organization copyTo(Organization org) {
        Objects.requireNonNull(org);
        org.setName(name);
        org.setShortName(shortName);
        org.setEmail(email);
        org.setUrl(url);
        org.setCountry(country);
        org.setLogo(logo);
        org.setType(type);
        org.setOidcClientName(oidcClientName);
        org.setOidcClientSecret(oidcClientSecret);
        org.setOidcWellKnownUrl(oidcWellKnownUrl);
        org.setPasswordHash(passwordHash);
        return org;
    }

    /** Copies this organization into the other.
     * Only updates OIDC if non-null content is given, skips password and shortname */
    public Organization selectiveCopyTo(Organization org) {
        Objects.requireNonNull(org);
        org.setName(name);
        org.setEmail(email);
        org.setUrl(url);
        org.setCountry(country);
        org.setLogo(logo);
        org.setType(type);
        if (oidcClientName != null) {
            org.setOidcClientName(oidcClientName);
        }
        if (oidcClientSecret != null) {
            org.setOidcClientSecret(oidcClientSecret);
        }
        if (oidcWellKnownUrl != null) {
            org.setOidcWellKnownUrl(oidcWellKnownUrl);
        }
        return org;
    }

    /** Creates a copy of this organization */
    public Organization copy() {
        return copyTo(new Organization());
    }

    /******************************/
    /** Getters and setters      **/
    /******************************/
    @JsonIgnore
    @Override
    public Long getId() {
        return id;
    }

    @JsonIgnore
    @Override
    protected void setId(Long id) {
        this.id = id;
    }

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

    @JsonIgnore
    public String getOidcWellKnownUrl() {
        return oidcWellKnownUrl;
    }

    @JsonProperty
    public void setOidcWellKnownUrl(String oidcWellKnownUrl) {
        this.oidcWellKnownUrl = oidcWellKnownUrl;
    }

    @JsonIgnore
    public String getOidcClientName() {
        return oidcClientName;
    }

    @JsonProperty
    public void setOidcClientName(String oidcClientName) {
        this.oidcClientName = oidcClientName;
    }

    @JsonIgnore
    public String getOidcClientSecret() {
        return oidcClientSecret;
    }

    @JsonProperty
    public void setOidcClientSecret(String oidcClientSecret) {
        this.oidcClientSecret = oidcClientSecret;
    }

}