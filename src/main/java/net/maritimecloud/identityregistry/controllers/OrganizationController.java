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
import net.maritimecloud.identityregistry.model.database.*;
import net.maritimecloud.identityregistry.model.database.entities.Device;
import net.maritimecloud.identityregistry.model.database.entities.Service;
import net.maritimecloud.identityregistry.model.database.entities.User;
import net.maritimecloud.identityregistry.model.database.entities.Vessel;
import net.maritimecloud.identityregistry.services.CertificateService;
import net.maritimecloud.identityregistry.services.EntityService;
import net.maritimecloud.identityregistry.utils.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RestController;

import net.maritimecloud.identityregistry.exception.McBasicRestException;
import net.maritimecloud.identityregistry.services.OrganizationService;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.InternalServerErrorException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
public class OrganizationController extends BaseControllerWithCertificate {
    // These 4 services are used when deleting an organization
    @Autowired
    private EntityService<Device> deviceService;
    @Autowired
    private EntityService<Service> serviceService;
    @Autowired
    private EntityService<User> userService;
    @Autowired
    private EntityService<Vessel> vesselService;
    @Autowired
    private EntityService<Role> roleService;

    @Autowired
    private EmailUtil emailUtil;

    private OrganizationService organizationService;

    @Autowired
    private KeycloakAdminUtil keycloakAU;

    private CertificateService certificateService;

    private static final Logger logger = LoggerFactory.getLogger(OrganizationController.class);

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
        Organization newOrg = this.organizationService.save(input);
        // Send email to organization saying that the application is awaiting approval
        emailUtil.sendOrgAwaitingApprovalEmail(newOrg.getEmail(), newOrg.getName());
        // Send email to admin saying that an Organization is awaiting approval
        emailUtil.sendAdminOrgAwaitingApprovalEmail(newOrg.getName());
        return new ResponseEntity<Organization>(newOrg, HttpStatus.OK);
    }

    /**
     * Returns list of all unapproved organizations
     *
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/unapprovedorgs",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("hasRole('SITE_ADMIN')")
    public ResponseEntity<List<Organization>> getUnapprovedOrganizations(HttpServletRequest request) {
        List<Organization> orgs = this.organizationService.getUnapprovedOrganizations();
        return new ResponseEntity<List<Organization>>(orgs, HttpStatus.OK);
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
    @PreAuthorize("hasRole('SITE_ADMIN')")
    public ResponseEntity<Organization> approveOrganization(HttpServletRequest request, @PathVariable String shortName) throws McBasicRestException {
        // Admin Authentication
        /*if (!AccessControlUtil.hasAccessToOrg(this.adminOrg) || !AccessControlUtil.hasPermission(this.adminPermission)) {
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        }*/
        Organization org = this.organizationService.getOrganizationByShortName(shortName);
        if (org == null) {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
        if (org.getApproved()) {
            throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.ORG_ALREADY_APPROVED, request.getServletPath());
        }
        // Create the Identity Provider for the org
        if (org.getIdentityProviderAttributes() != null && !org.getIdentityProviderAttributes().isEmpty()) {
            keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
            try {
                keycloakAU.createIdentityProvider(org.getShortName().toLowerCase(), org.getIdentityProviderAttributes());
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
            keycloakAU.createUser(org.getShortName(), newPassword, org.getShortName(), "ADMIN", org.getEmail(), org.getShortName(), "MCADMIN", true, KeycloakAdminUtil.ADMIN_USER);
        } catch (IOException e) {
            throw new McBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCIdRegConstants.ERROR_CREATING_ADMIN_KC_USER, request.getServletPath());
        }
        Organization approvedOrg =  this.organizationService.save(org);
        // Add a MCADMIN role mapper to actually give the admin user admin rights.
        Role adminRole = new Role();
        adminRole.setIdOrganization(approvedOrg.getId());
        adminRole.setPermission("MCADMIN");
        adminRole.setRoleName("ROLE_ORG_ADMIN");
        roleService.save(adminRole);
        // Send email to the organization that it has been approved
        emailUtil.sendOrgApprovedEmail(org.getEmail(), org.getName(), org.getShortName(), newPassword);
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
    public ResponseEntity<List<Organization>> getOrganization(HttpServletRequest request) {
        List<Organization> orgs = this.organizationService.listAll();
        return new ResponseEntity<List<Organization>>(orgs, HttpStatus.OK);
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
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#shortName)")
    public ResponseEntity<?> updateOrganization(HttpServletRequest request, @PathVariable String shortName,
            @RequestBody Organization input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(shortName);
        if (org != null) {
            if (!shortName.equals(input.getShortName())) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
            }
            // If a well-known url and client id and secret was supplied, and it is different from the current data we create a new IDP, or update it.
            if (input.getIdentityProviderAttributes() != null && !input.getIdentityProviderAttributes().isEmpty()) {
                keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                // If the IDP setup is different we delete the old IDP in keycloak
                if (org.getIdentityProviderAttributes() != null && !org.getIdentityProviderAttributes().isEmpty()
                        && !IdentityProviderAttribute.listsEquals(org.getIdentityProviderAttributes(), input.getIdentityProviderAttributes())) {
                    keycloakAU.deleteIdentityProvider(input.getShortName());
                }
                try {
                    keycloakAU.createIdentityProvider(input.getShortName().toLowerCase(), input.getIdentityProviderAttributes());
                } catch (InternalServerErrorException e) {
                    throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.INVALID_IDP_URL, request.getServletPath());
                } catch (IOException e) {
                    throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.COULD_NOT_GET_DATA_FROM_IDP, request.getServletPath());
                }
            } else if (org.getIdentityProviderAttributes() != null && !org.getIdentityProviderAttributes().isEmpty()) {
                // Remove old IDP if new input doesn't contain IDP info
                keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                keycloakAU.deleteIdentityProvider(input.getShortName());
            }
            input.selectiveCopyTo(org);
            this.organizationService.save(org);
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Deletes an Organization
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}",
            method = RequestMethod.DELETE)
    @PreAuthorize("hasRole('SITE_ADMIN')")
    public ResponseEntity<?> deleteOrg(HttpServletRequest request, @PathVariable String orgShortName) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortNameDisregardApproved(orgShortName);
        if (org != null) {
            //  TODO: we need to do some sync'ing with the Service Registry.
            if (org.getIdentityProviderAttributes() != null && !org.getIdentityProviderAttributes().isEmpty()) {
                keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                keycloakAU.deleteIdentityProvider(org.getShortName().toLowerCase());
            }
            this.deviceService.deleteByOrg(org.getId());
            this.serviceService.deleteByOrg(org.getId());
            this.userService.deleteByOrg(org.getId());
            this.vesselService.deleteByOrg(org.getId());
            this.roleService.deleteByOrg(org.getId());
            this.organizationService.delete(org.getId());
            return new ResponseEntity<>(HttpStatus.OK);
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
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<PemCertificate> newOrgCert(HttpServletRequest request, @PathVariable String orgShortName) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            PemCertificate ret = this.issueCertificate(org, org, "organization", request);
            return new ResponseEntity<PemCertificate>(ret, HttpStatus.OK);
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
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<?> revokeOrgCert(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long certId,  @RequestBody CertificateRevocation input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            Certificate cert = this.certificateService.getCertificateById(certId);
            Organization certOrg = cert.getOrganization();
            if (certOrg != null && certOrg.getId().compareTo(org.getId()) == 0) {
                this.revokeCertificate(certId, input, request);
                return new ResponseEntity<>(HttpStatus.OK);
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    protected String getName(CertificateModel certOwner) {
        return ((Organization)certOwner).getName();
    }

    @Override
    protected String getUid(CertificateModel certOwner) {
        return ((Organization)certOwner).getShortName();
    }

    protected String getEmail(CertificateModel certOwner) {
        return ((Organization)certOwner).getEmail();
    }
}
