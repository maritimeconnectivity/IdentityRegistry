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

import net.maritimecloud.identityregistry.model.database.CertificateModel;
import net.maritimecloud.identityregistry.services.EntityService;
import net.maritimecloud.identityregistry.utils.*;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.ApiOperation;
import net.maritimecloud.identityregistry.exception.McBasicRestException;
import net.maritimecloud.identityregistry.model.database.Certificate;
import net.maritimecloud.identityregistry.model.data.CertificateRevocation;
import net.maritimecloud.identityregistry.model.database.Organization;
import net.maritimecloud.identityregistry.model.data.PemCertificate;
import net.maritimecloud.identityregistry.model.database.entities.User;
import net.maritimecloud.identityregistry.services.UserService;

import java.io.IOException;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

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
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<User> createUser(HttpServletRequest request, @PathVariable String orgMrn, @Valid @RequestBody User input, BindingResult bindingResult) throws McBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // If the organization doesn't have its own Identity Provider we create the user in a special keycloak instance
            if (org.getIdentityProviderAttributes() == null || org.getIdentityProviderAttributes().isEmpty()) {
                String password = PasswordUtil.generatePassword();
                keycloakAU.init(KeycloakAdminUtil.USER_INSTANCE);
                try {
                    keycloakAU.createUser(input.getMrn(), password, input.getFirstName(), input.getLastName(), input.getEmail(), orgMrn, input.getPermissions(), true);
                } catch (IOException e) {
                    throw new McBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCIdRegConstants.ERROR_CREATING_KC_USER, request.getServletPath());
                }
                // Send email to user with credentials
                emailUtil.sendUserCreatedEmail(input.getEmail(), input.getFirstName() + " " + input.getLastName(), input.getEmail(), password);
            }
            input.setIdOrganization(org.getId());
            try {
                User newUser = this.entityService.save(input);
                return new ResponseEntity<User>(newUser, HttpStatus.OK);
            } catch (DataIntegrityViolationException e) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, e.getRootCause().getMessage(), request.getServletPath());
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
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> updateUser(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String userMrn, @Valid @RequestBody User input, BindingResult bindingResult) throws McBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        if (!userMrn.equals(input.getMrn())) {
            throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
        }
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            User user = this.entityService.getByMrn(userMrn);
            if (user == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.USER_NOT_FOUND, request.getServletPath());
            }
            if (!user.getMrn().equals(input.getMrn()) || user.getIdOrganization().compareTo(org.getId()) != 0) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
            }
            // Update user in keycloak if created there.
            if (org.getIdentityProviderAttributes() == null || org.getIdentityProviderAttributes().isEmpty()) {
                keycloakAU.init(KeycloakAdminUtil.USER_INSTANCE);
                try {
                    keycloakAU.updateUser(input.getMrn(), input.getFirstName(), input.getLastName(), input.getEmail(), input.getPermissions(), true);
                } catch (IOException e) {
                    throw new McBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCIdRegConstants.ERROR_UPDATING_KC_USER, request.getServletPath());
                }
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
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> deleteUser(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String userMrn) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
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
    public ResponseEntity<List<User>> getOrganizationUsers(HttpServletRequest request, @PathVariable String orgMrn) throws McBasicRestException {
        return this.getOrganizationEntities(request, orgMrn);
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
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<PemCertificate> newUserCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String userMrn) throws McBasicRestException {
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
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> revokeUserCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String userMrn, @PathVariable Long certId, @Valid @RequestBody CertificateRevocation input) throws McBasicRestException {
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
    public ResponseEntity<?> syncUser(HttpServletRequest request, @PathVariable String orgMrn, @RequestBody User input) throws McBasicRestException {
        if (!AccessControlUtil.isUserSync(this.userSyncMRN, this.userSyncO, this.userSyncOU, this.userSyncC)) {
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        }
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            String userMrn = input.getMrn();
            if (userMrn == null || userMrn.isEmpty()) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.USER_NOT_FOUND, request.getServletPath());
            }
            User oldUser = ((UserService)this.entityService).getUserByUserOrgIdAndIdOrganization(userMrn, org.getId());
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

