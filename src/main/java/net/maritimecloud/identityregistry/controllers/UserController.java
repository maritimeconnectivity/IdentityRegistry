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

import io.swagger.annotations.ApiOperation;
import net.maritimecloud.identityregistry.exception.McBasicRestException;
import net.maritimecloud.identityregistry.model.database.Certificate;
import net.maritimecloud.identityregistry.model.data.CertificateRevocation;
import net.maritimecloud.identityregistry.model.database.Organization;
import net.maritimecloud.identityregistry.model.data.PemCertificate;
import net.maritimecloud.identityregistry.model.database.entities.User;
import net.maritimecloud.identityregistry.services.CertificateService;
import net.maritimecloud.identityregistry.services.OrganizationService;
import net.maritimecloud.identityregistry.services.UserService;
import net.maritimecloud.identityregistry.utils.AccessControlUtil;
import net.maritimecloud.identityregistry.utils.CertificateUtil;
import net.maritimecloud.identityregistry.utils.KeycloakAdminUtil;
import net.maritimecloud.identityregistry.utils.MCIdRegConstants;
import net.maritimecloud.identityregistry.utils.PasswordUtil;

import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
@RequestMapping(value={"oidc", "x509"})
public class UserController {
    // Data that identifies the User sync'er
    @Value("${net.maritimecloud.idreg.user-sync.c}")
    private String userSyncC;
    @Value("${net.maritimecloud.idreg.user-sync.o}")
    private String userSyncO;
    @Value("${net.maritimecloud.idreg.user-sync.ou}")
    private String userSyncOU;
    @Value("${net.maritimecloud.idreg.user-sync.cn}")
    private String userSyncCN;

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

    @Autowired
    private CertificateUtil certUtil;

    /**
     * Creates a new User
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */ 
    @RequestMapping(
            value = "/api/org/{orgShortName}/user",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<User> createUser(HttpServletRequest request, @PathVariable String orgShortName, @RequestBody User input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                // Check for missing input
                if (input.getUserOrgId() == null || input.getUserOrgId().trim().isEmpty()) {
                    throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.ENTITY_ORG_ID_MISSING, request.getServletPath());
                }
                // Check that the userOrgId has the right format
                if (!input.getUserOrgId().equals(input.getUserOrgId().toLowerCase()) || !input.getUserOrgId().startsWith(orgShortName.toLowerCase() + ".")) {
                    throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.WRONG_ENTITY_ORG_ID_FORMAT, request.getServletPath());
                }
                String password = null;
                // If the organization doesn't have its own Identity Provider we create the user in a special keycloak instance
                if (org.getOidcClientName() == null || org.getOidcClientName().trim().isEmpty()) {
                    password = PasswordUtil.generatePassword();
                    keycloakAU.init(KeycloakAdminUtil.USER_INSTANCE);
                    try {
                        keycloakAU.createUser(input.getUserOrgId(), password, input.getFirstName(), input.getLastName(), input.getEmail(), orgShortName, input.getPermissions(), true, KeycloakAdminUtil.NORMAL_USER);
                    } catch (IOException e) {
                        throw new McBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCIdRegConstants.ERROR_CREATING_KC_USER, request.getServletPath());
                    }
                }
                input.setIdOrganization(org.getId());
                User newUser = this.userService.saveUser(input);
                if (password != null) {
                    newUser.setPassword(password);
                }
                return new ResponseEntity<User>(newUser, HttpStatus.OK);
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns info about the user identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/user/{userId}",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<User> getUser(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long userId) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                User user = this.userService.getUserById(userId);
                if (user == null) {
                    throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.USER_NOT_FOUND, request.getServletPath());
                }
                if (user.getIdOrganization().compareTo(org.getId()) == 0) {
                    return new ResponseEntity<User>(user, HttpStatus.OK);
                }
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
                
    }

    /**
     * Updates a User
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/user/{userId}",
            method = RequestMethod.PUT)
    @ResponseBody
    public ResponseEntity<?> updateUser(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long userId, @RequestBody User input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                User user = this.userService.getUserById(userId);
                if (user == null) {
                    throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.USER_NOT_FOUND, request.getServletPath());
                }
                if (user.getUserOrgId() != input.getUserOrgId() || user.getIdOrganization().compareTo(org.getId()) != 0) {
                    throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
                }
                // Update user in keycloak if created there.
                if (org.getOidcClientName() == null || org.getOidcClientName().trim().isEmpty()) {
                    keycloakAU.init(KeycloakAdminUtil.USER_INSTANCE);
                    try {
                        keycloakAU.updateUser(input.getUserOrgId(), input.getFirstName(), input.getLastName(), input.getEmail(), input.getPermissions(), true);
                    } catch (IOException e) {
                        throw new McBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCIdRegConstants.ERROR_UPDATING_KC_USER, request.getServletPath());
                    }
                }
                input.selectiveCopyTo(user);
                this.userService.saveUser(user);
                return new ResponseEntity<>(HttpStatus.OK);
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Deletes a User
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/user/{userId}",
            method = RequestMethod.DELETE)
    @ResponseBody
    public ResponseEntity<?> deleteUser(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long userId) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                User user = this.userService.getUserById(userId);
                if (user == null) {
                    throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.USER_NOT_FOUND, request.getServletPath());
                }
                if (user.getIdOrganization().compareTo(org.getId()) == 0) {
                    this.userService.deleteUser(userId);
                    // Remove user from keycloak if created there.
                    if (org.getOidcClientName() == null || org.getOidcClientName().trim().isEmpty()) {
                        keycloakAU.init(KeycloakAdminUtil.USER_INSTANCE);
                        keycloakAU.deleteUser(user.getUserOrgId());
                    }
                    return new ResponseEntity<>(HttpStatus.OK);
                }
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns a list of users belonging to the organization identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/users",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<List<User>> getOrganizationUsers(HttpServletRequest request, @PathVariable String orgShortName) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                List<User> users = this.userService.listOrgUsers(org.getId());
                return new ResponseEntity<List<User>>(users, HttpStatus.OK);
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
            value = "/api/org/{orgShortName}/user/{userId}/generatecertificate",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<PemCertificate> newUserCert(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long userId) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                User user = this.userService.getUserById(userId);
                if (user == null) {
                    throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.USER_NOT_FOUND, request.getServletPath());
                }
                if (user.getIdOrganization().compareTo(org.getId()) == 0) {
                    // Create the certificate and save it so that it gets an id that can be used as certificate serialnumber
                    Certificate newMCCert = new Certificate();
                    newMCCert.setUser(user);
                    newMCCert = this.certificateService.saveCertificate(newMCCert);
                    // Generate keypair for user
                    KeyPair userKeyPair = CertificateUtil.generateKeyPair();
                    // Find special MC attributes to put in the certificate
                    HashMap<String, String> attrs = new HashMap<String, String>();
                    if (user.getMrn() != null) {
                        attrs.put(CertificateUtil.MC_OID_MRN, user.getMrn());
                    }
                    if (user.getPermissions() != null) {
                        attrs.put(CertificateUtil.MC_OID_PERMISSIONS, user.getPermissions());
                    }
                    String name = user.getFirstName() + " " + user.getLastName();
                    String o = org.getShortName() + ";" + org.getName();
                    X509Certificate userCert = certUtil.generateCertForEntity(newMCCert.getId(), org.getCountry(), o, "user", name, user.getEmail(), userKeyPair.getPublic(), attrs);
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
                    newMCCert.setUser(user);
                    this.certificateService.saveCertificate(newMCCert);
                    return new ResponseEntity<PemCertificate>(ret, HttpStatus.OK);
                }
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
            value = "/api/org/{orgShortName}/user/{userId}/certificates/{certId}/revoke",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<?> revokeUserCert(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long userId, @PathVariable Long certId,  @RequestBody CertificateRevocation input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                User user = this.userService.getUserById(userId);
                if (user == null) {
                    throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.USER_NOT_FOUND, request.getServletPath());
                }
                if (user.getIdOrganization().compareTo(org.getId()) == 0) {
                    Certificate cert = this.certificateService.getCertificateById(certId);
                    User certUser = cert.getUser();
                    if (certUser != null && certUser.getId().compareTo(user.getId()) == 0) {
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
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Sync user from keycloak, diff from create/update user is that this should only be done by
     * the keycloak sync-mechanism. 
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */ 
    @ApiOperation(hidden=true, value = "Sync user from keycloak")
    @RequestMapping(
            value = "/api/org/{orgShortName}/user-sync/",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<?> syncUser(HttpServletRequest request, @PathVariable String orgShortName, @RequestBody User input) throws McBasicRestException {
        if (!AccessControlUtil.isUserSync(this.userSyncCN, this.userSyncO, this.userSyncOU, this.userSyncC)) {
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        }
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            String userOrgId = input.getUserOrgId();
            if (userOrgId == null || userOrgId.isEmpty()) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.USER_NOT_FOUND, request.getServletPath());
            }
            User oldUser = this.userService.getUserByUserOrgIdAndIdOrganization(userOrgId, org.getId());
            // If user does not exists, we create him
            if (oldUser == null) {
                input.setIdOrganization(org.getId());
                this.userService.saveUser(input);
            } else {
                // Update the existing user and save
                oldUser = input.selectiveCopyTo(oldUser);
                this.userService.saveUser(oldUser);
            }
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

}

