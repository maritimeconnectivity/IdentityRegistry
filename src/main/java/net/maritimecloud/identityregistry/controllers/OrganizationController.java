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
package net.maritimecloud.identityregistry.controllers;

import org.springframework.web.bind.annotation.RestController;

import net.maritimecloud.identityregistry.model.Organization;
import net.maritimecloud.identityregistry.services.OrganizationService;
import net.maritimecloud.identityregistry.utils.AccessControlUtil;
import net.maritimecloud.identityregistry.utils.CertificateUtil;
import net.maritimecloud.identityregistry.utils.KeycloakUtil;
import net.maritimecloud.identityregistry.utils.MCIdRegConstants;
import net.maritimecloud.identityregistry.utils.PasswordUtil;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.Principal;
import java.util.Locale;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
@RequestMapping(value={"admin", "oidc", "x509"})
public class OrganizationController {
    private OrganizationService organizationService;

    @Autowired
    public void setOrganizationService(OrganizationService organizationService) {
        this.organizationService = organizationService;
    }

    /**
     * Receives an application for a new organization and root-user
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/apply",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<?> applyOrganization(HttpServletRequest request, @RequestBody Organization input) {
        // Create password to be returned
        String newPassword = PasswordUtil.generatePassword();
        String hashedPassword = PasswordUtil.hashPassword(newPassword);
        input.setPassword(newPassword);
        input.setPasswordHash(hashedPassword);
        Organization newOrg = this.organizationService.saveOrganization(input);
        // If a well-known url and client id and secret was supplied, we create a new IDP
        if (input.getOidcWellKnownUrl() != null && !input.getOidcWellKnownUrl().isEmpty() 
                && input.getOidcClientName() != null && !input.getOidcClientName().isEmpty()
                && input.getOidcClientSecret() != null && !input.getOidcClientSecret().isEmpty()) {
            KeycloakUtil kcu = new KeycloakUtil();
            kcu.serviceAccountLogin();
            kcu.createIdentityProvider(input.getShortName().toLowerCase(), input.getOidcWellKnownUrl(), input.getOidcClientName(), input.getOidcClientSecret());
            kcu.getIDPs();
        }
        return new ResponseEntity<Organization>(newOrg, HttpStatus.OK);
    }

    /**
     * Returns info about the organization identified by the given ID
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{shortName}",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<?> getOrganization(HttpServletRequest request, @PathVariable String shortName) {
        Organization org = this.organizationService.getOrganizationByShortName(shortName);
        return new ResponseEntity<Organization>(org, HttpStatus.OK);
    }

    /**
     * Updates info about the organization identified by the given ID
     * 
     * @return a http reply
     */
    @RequestMapping(
            value = "/api/org/{shortName}",
            method = RequestMethod.PUT)
    public ResponseEntity<?> updateOrganization(HttpServletRequest request, @PathVariable String shortName,
            @RequestBody Organization input) {
        Organization org = this.organizationService.getOrganizationByShortName(shortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(org.getName(), shortName)) {
                input.copyTo(org);
                this.organizationService.saveOrganization(org);
                return new ResponseEntity<>(HttpStatus.OK);
            }
            return new ResponseEntity<>(MCIdRegConstants.MISSING_RIGHTS, HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(MCIdRegConstants.ORG_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Returns new password for the organization identified by the given ID
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{shortName}/getnewpassword",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<?> newOrgPassword(HttpServletRequest request, @PathVariable String shortName) {
        Organization org = this.organizationService.getOrganizationByShortName(shortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(org.getName(), shortName)) {
                String newPassword = PasswordUtil.generatePassword();
                String hashedPassword = PasswordUtil.hashPassword(newPassword);
                org.setPasswordHash(hashedPassword);
                this.organizationService.saveOrganization(org);
                String jsonReturn = "{ \"password\":\"" + newPassword + "\"}";
                return new ResponseEntity<String>(jsonReturn, HttpStatus.OK);
            }
            return new ResponseEntity<>(MCIdRegConstants.MISSING_RIGHTS, HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(MCIdRegConstants.ORG_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

}
