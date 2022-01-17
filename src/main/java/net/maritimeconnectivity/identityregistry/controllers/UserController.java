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
package net.maritimeconnectivity.identityregistry.controllers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.identityregistry.exception.DuplicatedKeycloakEntry;
import net.maritimeconnectivity.identityregistry.exception.McpBasicRestException;
import net.maritimeconnectivity.identityregistry.model.data.CertificateBundle;
import net.maritimeconnectivity.identityregistry.model.data.CertificateRevocation;
import net.maritimeconnectivity.identityregistry.model.database.Certificate;
import net.maritimeconnectivity.identityregistry.model.database.CertificateModel;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.model.database.Role;
import net.maritimeconnectivity.identityregistry.model.database.entities.User;
import net.maritimeconnectivity.identityregistry.services.EntityService;
import net.maritimeconnectivity.identityregistry.utils.AccessControlUtil;
import net.maritimeconnectivity.identityregistry.utils.EmailUtil;
import net.maritimeconnectivity.identityregistry.utils.KeycloakAdminUtil;
import net.maritimeconnectivity.identityregistry.utils.MCPIdRegConstants;
import net.maritimeconnectivity.identityregistry.utils.ValidateUtil;
import net.maritimeconnectivity.pki.pkcs11.P11PKIConfiguration;
import org.springdoc.api.annotations.ParameterObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Slf4j
@RestController
public class UserController extends EntityController<User> {
    // Data that identifies the User sync'er
    @Value("${net.maritimeconnectivity.idreg.user-sync.c}")
    private String userSyncC;
    @Value("${net.maritimeconnectivity.idreg.user-sync.o}")
    private String userSyncO;
    @Value("${net.maritimeconnectivity.idreg.user-sync.ou}")
    private String userSyncOU;
    @Value("${net.maritimeconnectivity.idreg.user-sync.mrn}")
    private String userSyncMRN;
    @Value("${net.maritimeconnectivity.idreg.allow-create-user-for-federated-org:true}")
    private boolean allowCreateUserForFederatedOrg;

    private static final String TYPE = "user";

    private KeycloakAdminUtil keycloakAU;

    private EmailUtil emailUtil;

    /**
     * Creates a new User
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/{orgMrn}/user",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @ResponseBody
    @PreAuthorize("hasRole('USER_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'USER_ADMIN')")
    @Transactional(rollbackFor = McpBasicRestException.class)
    public ResponseEntity<User> createUser(HttpServletRequest request, @PathVariable String orgMrn, @Valid @RequestBody User input, BindingResult bindingResult) throws McpBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        Organization org = this.organizationService.getOrganizationByMrnNoFilter(orgMrn);
        if (org != null) {
            // Check that the entity being created belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(input.getMrn()))) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            this.checkRoles(request, input, org);
            input.setMrn(input.getMrn().toLowerCase());
            input.setIdOrganization(org.getId());

            HttpHeaders headers = new HttpHeaders();
            User newUser = null;
            try {
                newUser = this.entityService.save(input);
                String path = request.getRequestURL().append("/").append(URLEncoder.encode(newUser.getMrn(), StandardCharsets.UTF_8)).toString();
                headers.setLocation(new URI(path));
            } catch (DataIntegrityViolationException e) {
                throw new McpBasicRestException(HttpStatus.CONFLICT, MCPIdRegConstants.ERROR_STORING_ENTITY, request.getServletPath());
            } catch (URISyntaxException e) {
                log.error("Could not create Location header", e);
            }
            // If the organization doesn't have its own Identity Provider we create the user in a special keycloak instance
            if ("test-idp".equals(org.getFederationType()) && (org.getIdentityProviderAttributes() == null || org.getIdentityProviderAttributes().isEmpty()) || allowCreateUserForFederatedOrg) {
                String password;
                if (certificateUtil.getPkiConfiguration() instanceof P11PKIConfiguration p11PKIConfiguration) {
                    p11PKIConfiguration.providerLogin();
                    password = passwordUtil.generatePassword();
                    p11PKIConfiguration.providerLogout();
                } else {
                    password = passwordUtil.generatePassword();
                }
                keycloakAU.init(KeycloakAdminUtil.USER_INSTANCE);
                try {
                    keycloakAU.checkUserExistence(newUser.getEmail());
                    keycloakAU.createUser(newUser, password, org, true);
                } catch (DuplicatedKeycloakEntry dke) {
                    throw new McpBasicRestException(HttpStatus.CONFLICT, dke.getErrorMessage(), request.getServletPath());
                } catch (IOException | NullPointerException e) {
                    throw new McpBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCPIdRegConstants.ERROR_CREATING_KC_USER, request.getServletPath());
                }
                // Send email to user with credentials
                emailUtil.sendUserCreatedEmail(newUser.getEmail(), newUser.getFirstName() + " " + newUser.getLastName(), newUser.getEmail(), password);
            } else if (("external-idp".equals(org.getFederationType()) || "own-idp".equals(org.getFederationType())) && !allowCreateUserForFederatedOrg) {
                throw new McpBasicRestException(HttpStatus.METHOD_NOT_ALLOWED, MCPIdRegConstants.ORG_IS_FEDERATED, request.getServletPath());
            }
            return new ResponseEntity<>(newUser, headers, HttpStatus.CREATED);
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns info about the user identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/user/{userMrn}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @ResponseBody
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn, null)")
    public ResponseEntity<User> getUser(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String userMrn) throws McpBasicRestException {
        return this.getEntity(request, orgMrn, userMrn);
    }

    /**
     * Updates a User
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PutMapping(
            value = "/api/org/{orgMrn}/user/{userMrn}"
    )
    @ResponseBody
    @PreAuthorize("hasRole('USER_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'USER_ADMIN')")
    public ResponseEntity<?> updateUser(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String userMrn, @Valid @RequestBody User input, BindingResult bindingResult) throws McpBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        if (!userMrn.equalsIgnoreCase(input.getMrn())) {
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
        }
        Organization org = this.organizationService.getOrganizationByMrnNoFilter(orgMrn);
        if (org != null) {
            // Check that the entity being updated belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(input.getMrn()))) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            this.checkRoles(request, input, org);
            User user = this.entityService.getByMrn(userMrn);
            if (user == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.USER_NOT_FOUND, request.getServletPath());
            }
            if (!user.getMrn().equalsIgnoreCase(input.getMrn()) || user.getIdOrganization().compareTo(org.getId()) != 0) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
            }
            input.selectiveCopyTo(user);
            User updatedUser = this.entityService.save(user);
            // Update user in keycloak if created there.
            if ("test-idp".equals(org.getFederationType()) && (org.getIdentityProviderAttributes() == null || org.getIdentityProviderAttributes().isEmpty())) {
                keycloakAU.init(KeycloakAdminUtil.USER_INSTANCE);
                try {
                    keycloakAU.updateUser(updatedUser.getMrn(), updatedUser.getFirstName(), updatedUser.getLastName(),
                            updatedUser.getEmail(), updatedUser.getPermissions(), updatedUser.constructDN(org),
                            updatedUser.getHomeMMSUrl(), updatedUser.getMrnSubsidiary(), request.getServletPath());
                } catch (IOException e) {
                    throw new McpBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCPIdRegConstants.ERROR_UPDATING_KC_USER, request.getServletPath());
                }
            }
            // If the org is federated they should only update their users in their own identity provider
            else if (("external-idp".equals(org.getFederationType()) || "own-idp".equals(org.getFederationType())) && !allowCreateUserForFederatedOrg) {
                throw new McpBasicRestException(HttpStatus.METHOD_NOT_ALLOWED, MCPIdRegConstants.ORG_IS_FEDERATED, request.getServletPath());
            }
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Deletes a User
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @DeleteMapping(
            value = "/api/org/{orgMrn}/user/{userMrn}"
    )
    @ResponseBody
    @PreAuthorize("hasRole('USER_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'USER_ADMIN')")
    public ResponseEntity<?> deleteUser(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String userMrn) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrnNoFilter(orgMrn);
        if (org != null) {
            // Check that the entity being deleted belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(userMrn))) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            User user = this.entityService.getByMrn(userMrn);
            if (user == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.USER_NOT_FOUND, request.getServletPath());
            }
            if (user.getIdOrganization().equals(org.getId())) {
                this.entityService.delete(user.getId());
                keycloakAU.deleteUser(user.getEmail(), user.getMrn());
                return new ResponseEntity<>(HttpStatus.OK);
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns a list of users belonging to the organization identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/users",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn, null)")
    public Page<User> getOrganizationUsers(HttpServletRequest request, @PathVariable String orgMrn, @ParameterObject Pageable pageable) throws McpBasicRestException {
        return this.getOrganizationEntities(request, orgMrn, pageable);
    }

    @GetMapping(
            value = "/api/org/{orgMrn}/user/{userMrn}/certificate/{serialNumber}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn, null)")
    public ResponseEntity<Certificate> getUserCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String userMrn, @PathVariable BigInteger serialNumber) throws McpBasicRestException {
        return this.getEntityCert(request, orgMrn, userMrn, TYPE, null, serialNumber);
    }

    /**
     * Returns new certificate for the user identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     * @deprecated It is generally not considered secure letting the server generate the private key. Will be removed in the future
     */
    @Operation(
            description = "DEPRECATED: Issues a bundle containing a certificate, the key pair of the certificate " +
                    "and keystores in JKS and PKCS#12 formats. As server generated key pairs are not considered secure " +
                    "this endpoint should not be used, and anybody who does should migrate to the endpoint for issuing " +
                    "certificates using certificate signing requests as soon as possible. This endpoint will be removed " +
                    "completely in the future and providers may choose to already disable it now which will result in an error if called."
    )
    @GetMapping(
            value = "/api/org/{orgMrn}/user/{userMrn}/certificate/issue-new",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @PreAuthorize("hasRole('USER_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'USER_ADMIN')")
    @Deprecated
    public ResponseEntity<CertificateBundle> newUserCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String userMrn) throws McpBasicRestException {
        return this.newEntityCert(request, orgMrn, userMrn, TYPE);
    }

    /**
     * Takes a certificate signing request and returns a signed certificate with the public key from the csr
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/{orgMrn}/user/{userMrn}/certificate/issue-new/csr",
            consumes = MediaType.TEXT_PLAIN_VALUE,
            produces = {"application/pem-certificate-chain", MediaType.APPLICATION_JSON_VALUE}
    )
    @PreAuthorize("(hasRole('USER_ADMIN') or @accessControlUtil.isUser(#userMrn)) and @accessControlUtil.hasAccessToOrg(#orgMrn, 'USER_ADMIN')")
    public ResponseEntity<String> newUserCertFromCsr(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String userMrn, @Parameter(description = "A PEM encoded PKCS#10 CSR", required = true) @RequestBody String csr) throws McpBasicRestException {
        return this.signEntityCert(request, csr, orgMrn, userMrn, TYPE, null);
    }

    /**
     * Revokes certificate for the user identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/{orgMrn}/user/{userMrn}/certificate/{certId}/revoke",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @PreAuthorize("hasRole('USER_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'USER_ADMIN')")
    public ResponseEntity<?> revokeUserCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String userMrn, @Parameter(description = "The serial number of the certificate given in decimal", required = true) @PathVariable BigInteger certId, @Valid @RequestBody CertificateRevocation input) throws McpBasicRestException {
        return this.revokeEntityCert(request, orgMrn, userMrn, certId, input);
    }

    /**
     * Sync user from keycloak, diff from create/update user is that this should only be done by
     * the keycloak sync-mechanism.
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @Operation(hidden = true, summary = "Sync user from keycloak")
    @PostMapping(
            value = "/api/org/{orgMrn}/user-sync/",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @ResponseBody
    public ResponseEntity<?> syncUser(HttpServletRequest request, @PathVariable String orgMrn, @RequestBody User input,
                                      @RequestParam(value = "org-name", required = false) String orgName,
                                      @RequestParam(value = "org-address", required = false) String orgAddress) throws McpBasicRestException {
        if (!AccessControlUtil.isUserSync(this.userSyncMRN, this.userSyncO, this.userSyncOU, this.userSyncC)) {
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        }
        Organization org = this.organizationService.getOrganizationByMrnNoFilter(orgMrn);
        // The organization does not exists - check if this a an organization hosted by an external "validator".
        if (org == null && orgAddress != null && orgName != null) {
            // Check that the org shortname is the same for the orgMrn and originalErrorMessage
            String orgShortname = mrnUtil.getOrgShortNameFromOrgMrn(orgMrn);
            if (!orgShortname.equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(input.getMrn()))) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
            }
            // Since the permissions of this user will be used as a template for administrator permissions, it must be
            // verified that the user actually has some permissions.
            if (input.getPermissions() == null || input.getPermissions().isEmpty()) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.ROLE_NOT_FOUND, request.getServletPath());
            }
            // Check validators?
            //String orgValidator = mrnUtil.getOrgValidatorFromOrgShortname(orgShortname);
            // The org validator is also CA
            String orgCa = certificateUtil.getDefaultSubCa();
            // Create the new org based on given info
            org = new Organization();
            org.setName(orgName);
            org.setMrn(orgMrn);
            org.setApproved(true);
            org.setEmail(input.getEmail());
            org.setCertificateAuthority(orgCa);
            // Extract domain-name from the user email and use that for org url.
            int at = input.getEmail().indexOf('@');
            String url = "http://" + input.getEmail().substring(at + 1);
            org.setUrl(url);
            // Extract country from address
            String country;
            String address;
            int lastComma = orgAddress.lastIndexOf(',');
            if (lastComma > 0) {
                country = orgAddress.substring(lastComma + 1).trim();
                address = orgAddress.substring(0, lastComma).trim();
            } else {
                country = "The Seven Seas";
                address = orgAddress;
            }
            org.setAddress(address);
            org.setCountry(country);
            org.setFederationType("external-idp");
            // save the new organization
            org = this.organizationService.save(org);
            // Create the initial roles for the organization. The permissions of the first user is used to define the ORG_ADMIN
            // Come on! That's a great idea!!
            if (input.getPermissions() != null) {
                for (String permission : input.getPermissions().split(",")) {
                    Role newRole = new Role();
                    newRole.setRoleName("ROLE_ORG_ADMIN");
                    newRole.setPermission(permission.trim());
                    newRole.setIdOrganization(org.getId());
                    this.roleService.save(newRole);
                }
            }
        }

        if (org != null) {
            String userMrn = input.getMrn();
            if (userMrn == null || userMrn.isEmpty()) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.USER_NOT_FOUND, request.getServletPath());
            }
            User oldUser = this.entityService.getByMrn(userMrn);
            // If user does not exists, we create him
            if (oldUser == null) {
                input.setIdOrganization(org.getId());
                this.entityService.save(input);
            } else {
                // Update the existing user and save
                oldUser = input.selectiveCopyTo(oldUser);
                this.entityService.save(oldUser);
            }
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    @Override
    protected String getName(CertificateModel certOwner) {
        return ((User) certOwner).getFirstName() + " " + ((User) certOwner).getLastName();
    }

    @Override
    protected String getEmail(CertificateModel certOwner) {
        return ((User) certOwner).getEmail();
    }

    @Override
    protected User getCertEntity(Certificate cert) {
        return cert.getUser();
    }

    @Autowired
    public void setKeycloakAU(KeycloakAdminUtil keycloakAU) {
        this.keycloakAU = keycloakAU;
    }

    @Autowired
    public void setEmailUtil(EmailUtil emailUtil) {
        this.emailUtil = emailUtil;
    }

    @Autowired
    public void setUserService(EntityService<User> userService) {
        this.entityService = userService;
    }
}
