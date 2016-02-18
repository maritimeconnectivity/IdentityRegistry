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

import net.maritimecloud.identityregistry.model.Certificate;
import net.maritimecloud.identityregistry.model.Organization;
import net.maritimecloud.identityregistry.model.User;
import net.maritimecloud.identityregistry.services.CertificateService;
import net.maritimecloud.identityregistry.services.OrganizationService;
import net.maritimecloud.identityregistry.services.UserService;
import net.maritimecloud.identityregistry.utils.AccessControlUtil;
import net.maritimecloud.identityregistry.utils.CertificateUtil;
import net.maritimecloud.identityregistry.utils.KeycloakAdminUtil;
import net.maritimecloud.identityregistry.utils.MCIdRegConstants;
import net.maritimecloud.identityregistry.utils.PasswordUtil;

import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
@RequestMapping(value={"admin", "oidc", "x509"})
public class UserController {
    private UserService userService;
    private OrganizationService organizationService;
    private CertificateService certificateService;

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setOrganizationService(OrganizationService organizationService) {
        this.organizationService = organizationService;
    }
    @Autowired
    public void setUserService(UserService organizationService) {
        this.userService = organizationService;
    }

    @Autowired
    private KeycloakAdminUtil keycloakAU;

    /**
     * Creates a new User
     * 
     * @return a reply...
     */ 
    @RequestMapping(
            value = "/api/org/{orgShortName}/user",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<?> createUser(HttpServletRequest request, @PathVariable String orgShortName, @RequestBody User input) {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(org.getName(), orgShortName)) {
                input.setIdOrganization(org.getId().intValue());
                User newUser = this.userService.saveUser(input);
                // If the organization doesn't have its own Identity Provider we create the user in a special keycloak instance
                if (org.getOidcClientName() == null && org.getOidcClientName().trim().isEmpty()) {
                    String password = PasswordUtil.generatePassword();
                    String keycloakUsername = orgShortName.toLowerCase() + "." + newUser.getUserOrgId();
                    keycloakAU.init(KeycloakAdminUtil.USER_INSTANCE);
                    keycloakAU.createUser(keycloakUsername, password, newUser.getFirstName(), newUser.getLastName(), newUser.getEmail(), orgShortName, KeycloakAdminUtil.NORMAL_USER);
                    newUser.setPassword(password);
                }
                return new ResponseEntity<User>(newUser, HttpStatus.OK);
            }
            return new ResponseEntity<>(MCIdRegConstants.MISSING_RIGHTS, HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(MCIdRegConstants.ORG_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Returns info about the user identified by the given ID
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/user/{userId}",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<?> getUser(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long userId) {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(org.getName(), orgShortName)) {
                User user = this.userService.getUserById(userId);
                if (user == null) {
                    return new ResponseEntity<>(MCIdRegConstants.USER_NOT_FOUND, HttpStatus.NOT_FOUND);
                }
                if (user.getIdOrganization() == org.getId().intValue()) {
                    return new ResponseEntity<User>(user, HttpStatus.OK);
                }
            }
            return new ResponseEntity<>(MCIdRegConstants.MISSING_RIGHTS, HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(MCIdRegConstants.ORG_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
                
    }

    /**
     * Updates a User
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/user/{userId}",
            method = RequestMethod.PUT)
    @ResponseBody
    public ResponseEntity<?> updateUser(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long userId, @RequestBody User input) {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(org.getName(), orgShortName)) {
                User user = this.userService.getUserById(userId);
                if (user == null) {
                    return new ResponseEntity<>(MCIdRegConstants.USER_NOT_FOUND, HttpStatus.NOT_FOUND);
                }
                if (user.getUserOrgId() != input.getUserOrgId()) {
                    return new ResponseEntity<>(MCIdRegConstants.URL_DATA_MISMATCH, HttpStatus.BAD_REQUEST);
                }
                if (user.getId() == input.getId() && user.getIdOrganization() == org.getId().intValue()) {
                    input.copyTo(user);
                    this.userService.saveUser(user);
                    // Update user in keycloak if created there.
                    if (org.getOidcClientName() == null && org.getOidcClientName().trim().isEmpty()) {
                        String keycloakUsername = orgShortName.toLowerCase() + "." + user.getUserOrgId();
                        keycloakAU.init(KeycloakAdminUtil.USER_INSTANCE);
                        keycloakAU.updateUser(keycloakUsername, user.getFirstName(), user.getLastName(), user.getEmail());
                    }
                    return new ResponseEntity<>(HttpStatus.OK);
                }
            }
            return new ResponseEntity<>(MCIdRegConstants.MISSING_RIGHTS, HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(MCIdRegConstants.ORG_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Deletes a User
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/user/{userId}",
            method = RequestMethod.DELETE)
    @ResponseBody
    public ResponseEntity<?> deleteUser(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long userId) {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(org.getName(), orgShortName)) {
                User user = this.userService.getUserById(userId);
                if (user == null) {
                    return new ResponseEntity<>(MCIdRegConstants.USER_NOT_FOUND, HttpStatus.NOT_FOUND);
                }
                if (user.getIdOrganization() == org.getId().intValue()) {
                    this.userService.deleteUser(userId);
                    // Remove user from keycloak if created there.
                    if (org.getOidcClientName() == null && org.getOidcClientName().trim().isEmpty()) {
                        String keycloakUsername = orgShortName.toLowerCase() + "." + user.getUserOrgId();
                        keycloakAU.init(KeycloakAdminUtil.USER_INSTANCE);
                        keycloakAU.deleteUser(keycloakUsername);
                    }
                    return new ResponseEntity<>(HttpStatus.OK);
                }
            }
            return new ResponseEntity<>(MCIdRegConstants.MISSING_RIGHTS, HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(MCIdRegConstants.ORG_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Returns a list of users belonging to the organization identified by the given ID
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/users",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<?> getOrganizationUsers(HttpServletRequest request, @PathVariable String orgShortName) {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(org.getName(), orgShortName)) {
                List<User> users = this.userService.listOrgUsers(org.getId().intValue());
                return new ResponseEntity<List<User>>(users, HttpStatus.OK);
            }
            return new ResponseEntity<>(MCIdRegConstants.MISSING_RIGHTS, HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(MCIdRegConstants.ORG_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Returns new certificate for the user identified by the given ID
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/user/{userId}/generatecertificate",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<?> newUserCert(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long userId) {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(org.getName(), orgShortName)) {
                User user = this.userService.getUserById(userId);
                if (user == null) {
                    return new ResponseEntity<>(MCIdRegConstants.USER_NOT_FOUND, HttpStatus.NOT_FOUND);
                }
                if (user.getIdOrganization() == org.getId().intValue()) {
                    // Create the certificate and save it so that it gets an id that can be use as certificate serialnumber
                    Certificate newMCCert = new Certificate();
                    newMCCert.setUser(user);
                    newMCCert = this.certificateService.saveCertificate(newMCCert);
                    // Generate keypair for user
                    KeyPair userKeyPair = CertificateUtil.generateKeyPair();
                    X509Certificate userCert = CertificateUtil.generateCertForEntity(newMCCert.getId(), org.getCountry(), org.getName(), user.getFirstName(), user.getFirstName(), user.getEmail(), userKeyPair.getPublic());
                    String pemCertificate = "";
                    try {
                        pemCertificate = CertificateUtil.getPemFromEncoded("CERTIFICATE", userCert.getEncoded());
                    } catch (CertificateEncodingException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                    String pemPublicKey = CertificateUtil.getPemFromEncoded("PUBLIC KEY", userKeyPair.getPublic().getEncoded());
                    String pemPrivateKey = CertificateUtil.getPemFromEncoded("PRIVATE KEY", userKeyPair.getPrivate().getEncoded());
                    newMCCert.setCertificate(pemCertificate);
                    newMCCert.setStart(userCert.getNotBefore());
                    newMCCert.setEnd(userCert.getNotAfter());
                    newMCCert.setUser(user);
                    this.certificateService.saveCertificate(newMCCert);
                    String jsonReturn = "{ \"publickey\":\"" + pemPublicKey + "\", \"privatekey\":\"" + pemPrivateKey + "\", \"certificate\":\"" + pemCertificate + "\"  }";

                    return new ResponseEntity<String>(jsonReturn, HttpStatus.OK);
                }
            }
            return new ResponseEntity<>(MCIdRegConstants.MISSING_RIGHTS, HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(MCIdRegConstants.ORG_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Revokes certificate for the user identified by the given ID
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/user/{userId}/revokecertificate/{certId}",
            method = RequestMethod.DELETE,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<?> revokeUserCert(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long userId, @PathVariable Long certId) {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(org.getName(), orgShortName)) {
                User user = this.userService.getUserById(userId);
                if (user == null) {
                    return new ResponseEntity<>(MCIdRegConstants.USER_NOT_FOUND, HttpStatus.NOT_FOUND);
                }
                if (user.getIdOrganization() == org.getId().intValue()) {
                    Certificate cert = this.certificateService.getCertificateById(certId);
                    User certUser = cert.getUser();
                    if (certUser != null && certUser.getId().equals(user.getId())) {
                        cert.setRevoked(true);
                        this.certificateService.saveCertificate(cert);
                        return new ResponseEntity<>(HttpStatus.OK);
                    }
                }
            }
            return new ResponseEntity<>(MCIdRegConstants.MISSING_RIGHTS, HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(MCIdRegConstants.ORG_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

}

