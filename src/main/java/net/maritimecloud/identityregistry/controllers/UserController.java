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
package net.maritimecloud.identityregistry.controllers;

import io.swagger.annotations.ApiOperation;
import net.maritimecloud.identityregistry.exception.DuplicatedKeycloakEntry;
import net.maritimecloud.identityregistry.exception.McBasicRestException;
import net.maritimecloud.identityregistry.model.data.CertificateBundle;
import net.maritimecloud.identityregistry.model.data.CertificateRevocation;
import net.maritimecloud.identityregistry.model.database.Certificate;
import net.maritimecloud.identityregistry.model.database.CertificateModel;
import net.maritimecloud.identityregistry.model.database.Organization;
import net.maritimecloud.identityregistry.model.database.Role;
import net.maritimecloud.identityregistry.model.database.entities.User;
import net.maritimecloud.identityregistry.services.EntityService;
import net.maritimecloud.identityregistry.services.RoleService;
import net.maritimecloud.identityregistry.utils.AccessControlUtil;
import net.maritimecloud.identityregistry.utils.EmailUtil;
import net.maritimecloud.identityregistry.utils.KeycloakAdminUtil;
import net.maritimecloud.identityregistry.utils.MCIdRegConstants;
import net.maritimecloud.identityregistry.utils.MrnUtil;
import net.maritimecloud.identityregistry.utils.PasswordUtil;
import net.maritimecloud.identityregistry.utils.ValidateUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.io.IOException;
import java.math.BigInteger;

@RestController
public class UserController extends EntityController<User> {
    // Data that identifies the User sync'er
    @Value("${net.maritimecloud.idreg.user-sync.c}")
    private String userSyncC;
    @Value("${net.maritimecloud.idreg.user-sync.o}")
    private String userSyncO;
    @Value("${net.maritimecloud.idreg.user-sync.ou}")
    private String userSyncOU;
    @Value("${net.maritimecloud.idreg.user-sync.mrn}")
    private String userSyncMRN;

    @Autowired
    public void setUserService(EntityService<User> userService) {
        this.entityService = userService;
    }

    @Autowired
    private RoleService roleService;

    @Autowired
    private KeycloakAdminUtil keycloakAU;
    @Autowired
    private EmailUtil emailUtil;

    /**
     * Creates a new User
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */ 
    @RequestMapping(
            value = "/api/org/{orgMrn}/user",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    @PreAuthorize("hasRole('USER_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<User> createUser(HttpServletRequest request, @PathVariable String orgMrn, @Valid @RequestBody User input, BindingResult bindingResult) throws McBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being created belongs to the organization
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(MrnUtil.getOrgShortNameFromEntityMrn(input.getMrn()))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            input.setMrn(input.getMrn().toLowerCase());
            // If the organization doesn't have its own Identity Provider we create the user in a special keycloak instance
            if ("test-idp".equals(org.getFederationType()) && (org.getIdentityProviderAttributes() == null || org.getIdentityProviderAttributes().isEmpty())) {
                String password = PasswordUtil.generatePassword();
                keycloakAU.init(KeycloakAdminUtil.USER_INSTANCE);
                try {
                    keycloakAU.checkUserExistence(input.getEmail());
                    keycloakAU.createUser(input.getMrn(), password, input.getFirstName(), input.getLastName(), input.getEmail(), orgMrn, input.getPermissions(), true);
                } catch (DuplicatedKeycloakEntry dke) {
                    throw new McBasicRestException(HttpStatus.CONFLICT, dke.getErrorMessage(), request.getServletPath());
                } catch (IOException e) {
                    throw new McBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCIdRegConstants.ERROR_CREATING_KC_USER, request.getServletPath());
                }
                // Send email to user with credentials
                emailUtil.sendUserCreatedEmail(input.getEmail(), input.getFirstName() + " " + input.getLastName(), input.getEmail(), password);
            } else if ("external-idp".equals(org.getFederationType()) || "own-idp".equals(org.getFederationType())) {
                throw new McBasicRestException(HttpStatus.METHOD_NOT_ALLOWED, MCIdRegConstants.ORG_IS_FEDERATED, request.getServletPath());
            }
            input.setIdOrganization(org.getId());
            try {
                User newUser = this.entityService.save(input);
                return new ResponseEntity<>(newUser, HttpStatus.OK);
            } catch (DataIntegrityViolationException e) {
                // If save to DB failed, remove the user from keycloak if it was created.
                if ("test-idp".equals(org.getFederationType()) && (org.getIdentityProviderAttributes() == null || org.getIdentityProviderAttributes().isEmpty())) {
                    keycloakAU.deleteUser(input.getEmail());
                }
                throw new McBasicRestException(HttpStatus.CONFLICT, e.getRootCause().getMessage(), request.getServletPath());
            }
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
            value = "/api/org/{orgMrn}/user/{userMrn}",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<User> getUser(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String userMrn) throws McBasicRestException {
        return this.getEntity(request, orgMrn, userMrn);
    }

    /**
     * Updates a User
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/user/{userMrn}",
            method = RequestMethod.PUT)
    @ResponseBody
    @PreAuthorize("hasRole('USER_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> updateUser(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String userMrn, @Valid @RequestBody User input, BindingResult bindingResult) throws McBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        if (!userMrn.equalsIgnoreCase(input.getMrn())) {
            throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
        }
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being updated belongs to the organization
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(MrnUtil.getOrgShortNameFromEntityMrn(input.getMrn()))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            User user = this.entityService.getByMrn(userMrn);
            if (user == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.USER_NOT_FOUND, request.getServletPath());
            }
            if (!user.getMrn().equalsIgnoreCase(input.getMrn()) || user.getIdOrganization().compareTo(org.getId()) != 0) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
            }
            // Update user in keycloak if created there.
            if ("test-idp".equals(org.getFederationType()) && (org.getIdentityProviderAttributes() == null || org.getIdentityProviderAttributes().isEmpty())) {
                keycloakAU.init(KeycloakAdminUtil.USER_INSTANCE);
                try {
                    keycloakAU.updateUser(input.getMrn(), input.getFirstName(), input.getLastName(), input.getEmail(), input.getPermissions(), true);
                } catch (IOException e) {
                    throw new McBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCIdRegConstants.ERROR_UPDATING_KC_USER, request.getServletPath());
                }
            } else if ("external-idp".equals(org.getFederationType()) || "own-idp".equals(org.getFederationType())) {
                throw new McBasicRestException(HttpStatus.METHOD_NOT_ALLOWED, MCIdRegConstants.ORG_IS_FEDERATED, request.getServletPath());
            }
            input.selectiveCopyTo(user);
            this.entityService.save(user);
            return new ResponseEntity<>(HttpStatus.OK);
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
            value = "/api/org/{orgMrn}/user/{userMrn}",
            method = RequestMethod.DELETE)
    @ResponseBody
    @PreAuthorize("hasRole('USER_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> deleteUser(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String userMrn) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being deleted belongs to the organization
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(MrnUtil.getOrgShortNameFromEntityMrn(userMrn))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            User user = this.entityService.getByMrn(userMrn);
            if (user == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.USER_NOT_FOUND, request.getServletPath());
            }
            if (user.getIdOrganization().compareTo(org.getId()) == 0) {
                this.entityService.delete(user.getId());
                // Remove user from keycloak if created there.
                if (org.getIdentityProviderAttributes() == null || org.getIdentityProviderAttributes().isEmpty()) {
                    keycloakAU.init(KeycloakAdminUtil.USER_INSTANCE);
                    keycloakAU.deleteUser(user.getEmail());
                }
                return new ResponseEntity<>(HttpStatus.OK);
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
            value = "/api/org/{orgMrn}/users",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn)")
    public Page<User> getOrganizationUsers(HttpServletRequest request, @PathVariable String orgMrn, Pageable pageable) throws McBasicRestException {
        return this.getOrganizationEntities(request, orgMrn, pageable);
    }

    /**
     * Returns new certificate for the user identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/user/{userMrn}/certificate/issue-new",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("hasRole('USER_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<CertificateBundle> newUserCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String userMrn) throws McBasicRestException {
        return this.newEntityCert(request, orgMrn, userMrn, "user");
    }

    /**
     * Revokes certificate for the user identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/user/{userMrn}/certificate/{certId}/revoke",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("hasRole('USER_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> revokeUserCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String userMrn, @PathVariable BigInteger certId, @Valid @RequestBody CertificateRevocation input) throws McBasicRestException {
        return this.revokeEntityCert(request, orgMrn, userMrn, certId, input);
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
            value = "/api/org/{orgMrn}/user-sync/",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<?> syncUser(HttpServletRequest request, @PathVariable String orgMrn, @RequestBody User input,
                                      @RequestParam(value = "org-name", required = false) String orgName,
                                      @RequestParam(value = "org-address", required = false) String orgAddress) throws McBasicRestException {
        if (!AccessControlUtil.isUserSync(this.userSyncMRN, this.userSyncO, this.userSyncOU, this.userSyncC)) {
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        }
        Organization org = this.organizationService.getOrganizationByMrnNoFilter(orgMrn);
        // The organization does not exists - check if this a an organization hosted by an external "validator".
        if (org == null && orgAddress != null && orgName != null) {
            // Check that the org shortname is the same for the orgMrn and originalErrorMessage
            String orgShortname = MrnUtil.getOrgShortNameFromOrgMrn(orgMrn);
            if (!orgShortname.equalsIgnoreCase(MrnUtil.getOrgShortNameFromEntityMrn(input.getMrn()))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
            }
            // Since the permissions of this user will be used as a template for administrator permissions, it must be
            // verified that the user actually has some permissions.
            if (input.getPermissions() == null || input.getPermissions().isEmpty()) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.ROLE_NOT_FOUND, request.getServletPath());
            }
            // Check validators?
            String orgValidator = MrnUtil.getOrgValidatorFromOrgShortname(orgShortname);
            // The org validator is also CA
            String orgCa = "urn:mrn:mcl:ca:" + orgValidator;
            // Create the new org based on given info
            org = new Organization();
            org.setName(orgName);
            org.setMrn(orgMrn);
            org.setApproved(true);
            org.setEmail(input.getEmail());
            org.setCertificateAuthority(orgCa);
            // Extract domain-name from the user email and use that for org url.
            int at = input.getEmail().indexOf("@");
            String url = "http://" + input.getEmail().substring(at+1);
            org.setUrl(url);
            // Extract country from address
            String country;
            String address;
            int lastComma = orgAddress.lastIndexOf(",");
            if (lastComma > 0) {
                country = orgAddress.substring(lastComma+1).trim();
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
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.USER_NOT_FOUND, request.getServletPath());
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
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    protected String getName(CertificateModel certOwner) {
        return ((User)certOwner).getFirstName() + " " + ((User)certOwner).getLastName();
    }

    protected String getEmail(CertificateModel certOwner) {
        return ((User)certOwner).getEmail();
    }

    @Override
    protected User getCertEntity(Certificate cert) {
        return cert.getUser();
    }
}

