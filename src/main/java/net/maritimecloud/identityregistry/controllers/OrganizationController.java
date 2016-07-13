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

import net.maritimecloud.identityregistry.model.data.CertificateRevocation;
import net.maritimecloud.identityregistry.model.data.PemCertificate;
import net.maritimecloud.identityregistry.model.database.Organization;
import net.maritimecloud.identityregistry.model.database.Certificate;
import net.maritimecloud.identityregistry.services.CertificateService;
import net.maritimecloud.identityregistry.utils.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RestController;

import net.maritimecloud.identityregistry.exception.McBasicRestException;
import net.maritimecloud.identityregistry.services.OrganizationService;

import java.io.IOException;
import java.net.MalformedURLException;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
@RequestMapping(value={"oidc", "x509"})
public class OrganizationController {
    private OrganizationService organizationService;

    @Autowired
    private KeycloakAdminUtil keycloakAU;

    private CertificateService certificateService;

    private static final Logger logger = LoggerFactory.getLogger(OrganizationController.class);

    @Autowired
    private CertificateUtil certUtil;

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }


    @Autowired
    public void setOrganizationService(OrganizationService organizationService) {
        this.organizationService = organizationService;
    }

    @Value("${net.maritimecloud.idreg.admin-org}")
    private String adminOrg;

    @Value("${net.maritimecloud.idreg.admin-permission}")
    private String adminPermission;

    /**
     * Receives an application for a new organization and root-user
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/apply",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<Organization> applyOrganization(HttpServletRequest request, @RequestBody Organization input) throws McBasicRestException {
        // Make sure all shortnames are uppercase
        input.setShortName(input.getShortName().trim().toUpperCase());
        input.setApproved(false);
        Organization newOrg = this.organizationService.saveOrganization(input);
        // TODO: Send email to organization saying that the application is awaiting approval
        // TODO: Send email to admin saying that an Organization is awaiting approval
        return new ResponseEntity<Organization>(newOrg, HttpStatus.OK);
    }

    /**
     * Approves the organization identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{shortName}/approve",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<Organization> approveOrganization(HttpServletRequest request, @PathVariable String shortName) throws McBasicRestException {
        // Admin Authentication
        if (!AccessControlUtil.hasAccessToOrg(this.adminOrg) || !AccessControlUtil.hasPermission(this.adminPermission)) {
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        }
        Organization org = this.organizationService.getOrganizationByShortName(shortName);
        if (org == null) {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
        if (org.getApproved()) {
            throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.ORG_ALREADY_APPROVED, request.getServletPath());
        }
        // Create the Identity Provider for the org
        if (org.getOidcWellKnownUrl() != null && !org.getOidcWellKnownUrl().isEmpty()
                && org.getOidcClientName() != null && !org.getOidcClientName().isEmpty()
                && org.getOidcClientSecret() != null && !org.getOidcClientSecret().isEmpty()) {
            keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
            try {
                keycloakAU.createIdentityProvider(org.getShortName().toLowerCase(), org.getOidcWellKnownUrl(), org.getOidcClientName(), org.getOidcClientSecret());
            } catch (MalformedURLException e) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.INVALID_IDP_URL, request.getServletPath());
            } catch (IOException e) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.COULD_NOT_GET_DATA_FROM_IDP, request.getServletPath());
            }
        }
        // Enabled the organization and save it
        org.setApproved(true);
        // Create password to be send to admin
        String newPassword = PasswordUtil.generatePassword();
        // Create admin user in the keycloak instance handling users
        keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
        try {
            keycloakAU.createUser(org.getShortName(), newPassword, org.getShortName(), "ADMIN", org.getEmail(), org.getShortName(), "MCADMIN,MCUSER", true, KeycloakAdminUtil.ADMIN_USER);
        } catch (IOException e) {
            throw new McBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCIdRegConstants.ERROR_CREATING_ADMIN_KC_USER, request.getServletPath());
        }
        Organization approvedOrg =  this.organizationService.saveOrganization(org);
        // TODO: send email to organization with the happy news and the admin password
        approvedOrg.setPassword(newPassword);
        return new ResponseEntity<Organization>(approvedOrg, HttpStatus.OK);
    }


    /**
     * Returns info about the organization identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{shortName}",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<Organization> getOrganization(HttpServletRequest request, @PathVariable String shortName) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(shortName);
        if (org == null) {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
        return new ResponseEntity<Organization>(org, HttpStatus.OK);
    }

    /**
     * Returns list of all organizations
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/orgs",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<Iterable<Organization>> getOrganization(HttpServletRequest request) {
        Iterable<Organization> orgs = this.organizationService.listAllOrganizations();
        return new ResponseEntity<Iterable<Organization>>(orgs, HttpStatus.OK);
    }

    /**
     * Updates info about the organization identified by the given ID
     * 
     * @return a http reply
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{shortName}",
            method = RequestMethod.PUT)
    public ResponseEntity<?> updateOrganization(HttpServletRequest request, @PathVariable String shortName,
            @RequestBody Organization input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(shortName);
        if (org != null) {
            if (!shortName.equals(input.getShortName())) {
                throw new McBasicRestException(HttpStatus.BAD_GATEWAY, MCIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
            }
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(shortName)) {
                // If a well-known url and client id and secret was supplied, and it is different from the current data we create a new IDP, or update it.
                if (input.getOidcWellKnownUrl() != null && !input.getOidcWellKnownUrl().isEmpty()
                        && input.getOidcClientName() != null && !input.getOidcClientName().isEmpty()
                        && input.getOidcClientSecret() != null && !input.getOidcClientSecret().isEmpty()) {
                    keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                    // If client ids are different we delete the old IDP in keycloak
                    if (org.getOidcClientName() != null && !input.getOidcClientName().equals(org.getOidcClientName())) {
                        keycloakAU.deleteIdentityProvider(input.getShortName());
                    }
                    try {
                        keycloakAU.createIdentityProvider(input.getShortName().toLowerCase(), input.getOidcWellKnownUrl(), input.getOidcClientName(), input.getOidcClientSecret());
                    } catch (MalformedURLException e) {
                        throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.INVALID_IDP_URL, request.getServletPath());
                    } catch (IOException e) {
                        throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.COULD_NOT_GET_DATA_FROM_IDP, request.getServletPath());
                    }
                }
                // TODO: Remove old IDP if new input doesn't contain IDP info
                input.selectiveCopyTo(org);
                this.organizationService.saveOrganization(org);
                return new ResponseEntity<>(HttpStatus.OK);
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }


    /**
     * Returns new certificate for the user identified by the given ID
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/generatecertificate",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<PemCertificate> newOrgCert(HttpServletRequest request, @PathVariable String orgShortName) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                // Create the certificate and save it so that it gets an id that can be used as certificate serialnumber
                Certificate newMCCert = new Certificate();
                newMCCert.setOrganization(org);
                newMCCert = this.certificateService.saveCertificate(newMCCert);
                // Generate keypair for user
                KeyPair userKeyPair = CertificateUtil.generateKeyPair();
                // Find special MC attributes to put in the certificate
                HashMap<String, String> attrs = new HashMap<String, String>();
                String o = org.getShortName() + ";" + org.getName();
                X509Certificate userCert = certUtil.generateCertForEntity(newMCCert.getId(), org.getCountry(), o, "organization", org.getName(), org.getEmail(), userKeyPair.getPublic(), attrs);
                String pemCertificate = "";
                try {
                    pemCertificate = CertificateUtil.getPemFromEncoded("CERTIFICATE", userCert.getEncoded()).replace("\n", "\\n");
                } catch (CertificateEncodingException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                String pemPublicKey = CertificateUtil.getPemFromEncoded("PUBLIC KEY", userKeyPair.getPublic().getEncoded()).replace("\n", "\\n");
                String pemPrivateKey = CertificateUtil.getPemFromEncoded("PRIVATE KEY", userKeyPair.getPrivate().getEncoded()).replace("\n", "\\n");
                PemCertificate ret = new PemCertificate(pemPrivateKey, pemPublicKey, pemCertificate);
                newMCCert.setCertificate(pemCertificate);
                // The dates we extract from the cert is in localtime, so they are converted to UTC before saving into the DB
                Calendar cal = Calendar.getInstance();
                long offset = cal.get(Calendar.ZONE_OFFSET) + cal.get(Calendar.DST_OFFSET);
                newMCCert.setStart(new Date(userCert.getNotBefore().getTime() - offset));
                newMCCert.setEnd(new Date(userCert.getNotAfter().getTime() - offset));
                newMCCert.setOrganization(org);
                this.certificateService.saveCertificate(newMCCert);
                return new ResponseEntity<PemCertificate>(ret, HttpStatus.OK);
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Revokes certificate for the user identified by the given ID
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/certificates/{certId}/revoke",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<?> revokeUserCert(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long certId,  @RequestBody CertificateRevocation input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                Certificate cert = this.certificateService.getCertificateById(certId);
                Organization certOrg = cert.getOrganization();
                if (certOrg != null && certOrg.getId().compareTo(org.getId()) == 0) {
                    if (!input.validateReason()) {
                        throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.INVALID_REVOCATION_REASON, request.getServletPath());
                    }
                    if (input.getRevokedAt() == null) {
                        throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.INVALID_REVOCATION_DATE, request.getServletPath());
                    }
                    cert.setRevokedAt(input.getRevokedAt());
                    cert.setRevokeReason(input.getRevokationReason());
                    cert.setRevoked(true);
                    this.certificateService.saveCertificate(cert);
                    return new ResponseEntity<>(HttpStatus.OK);
                }
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }
}
