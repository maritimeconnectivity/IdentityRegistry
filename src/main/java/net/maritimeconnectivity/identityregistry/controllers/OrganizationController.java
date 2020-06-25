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

import io.swagger.annotations.ApiParam;
import net.maritimeconnectivity.identityregistry.exception.McBasicRestException;
import net.maritimeconnectivity.identityregistry.model.data.CertificateBundle;
import net.maritimeconnectivity.identityregistry.model.data.CertificateRevocation;
import net.maritimeconnectivity.identityregistry.model.database.Certificate;
import net.maritimeconnectivity.identityregistry.model.database.CertificateModel;
import net.maritimeconnectivity.identityregistry.model.database.IdentityProviderAttribute;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.model.database.entities.Device;
import net.maritimeconnectivity.identityregistry.model.database.entities.Service;
import net.maritimeconnectivity.identityregistry.model.database.entities.User;
import net.maritimeconnectivity.identityregistry.model.database.entities.Vessel;
import net.maritimeconnectivity.identityregistry.model.database.entities.MMS;
import net.maritimeconnectivity.identityregistry.services.AgentService;
import net.maritimeconnectivity.identityregistry.services.CertificateService;
import net.maritimeconnectivity.identityregistry.services.EntityService;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import net.maritimeconnectivity.identityregistry.services.RoleService;
import net.maritimeconnectivity.identityregistry.utils.CsrUtil;
import net.maritimeconnectivity.identityregistry.utils.EmailUtil;
import net.maritimeconnectivity.identityregistry.utils.KeycloakAdminUtil;
import net.maritimeconnectivity.identityregistry.utils.MCIdRegConstants;
import net.maritimeconnectivity.identityregistry.utils.ValidateUtil;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import javax.ws.rs.InternalServerErrorException;
import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.util.HashMap;

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
    private EntityService<MMS> mmsService;

    @Autowired
    private RoleService roleService;

    @Autowired
    private EmailUtil emailUtil;

    @Autowired
    private OrganizationService organizationService;

    @Autowired
    private KeycloakAdminUtil keycloakAU;

    @Autowired
    private CertificateService certificateService;

    @Autowired
    private AgentService agentService;

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
    public ResponseEntity<Organization> applyOrganization(HttpServletRequest request, @RequestBody @Valid Organization input, BindingResult bindingResult) throws McBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        // Make sure all mrn are lowercase
        input.setMrn(input.getMrn().trim().toLowerCase());
        input.setApproved(false);
        // If no federation type is set we for now default to "test-idp"
        if (input.getFederationType() == null || input.getFederationType().isEmpty()) {
            input.setFederationType("test-idp");
        }
        // Default to the MC IDR CA
        input.setCertificateAuthority(certificateUtil.getDefaultSubCa());
        Organization newOrg;
        try {
            newOrg = this.organizationService.save(input);
        } catch (DataIntegrityViolationException e) {
            throw new McBasicRestException(HttpStatus.BAD_REQUEST, e.getRootCause().getMessage(), request.getServletPath());
        }
        // Send email to organization saying that the application is awaiting approval
        emailUtil.sendOrgAwaitingApprovalEmail(newOrg.getEmail(), newOrg.getName());
        // Send email to admin saying that an Organization is awaiting approval
        emailUtil.sendAdminOrgAwaitingApprovalEmail(newOrg.getName(), newOrg.getMrn());
        return new ResponseEntity<>(newOrg, HttpStatus.OK);
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
    @PreAuthorize("hasRole('ROLE_APPROVE_ORG')")
    public Page<Organization> getUnapprovedOrganizations(Pageable pageable) {
        return this.organizationService.getUnapprovedOrganizations(pageable);
    }

    /**
     * Approves the organization identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/approve",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("hasRole('ROLE_APPROVE_ORG')")
    public ResponseEntity<Organization> approveOrganization(HttpServletRequest request, @PathVariable String orgMrn) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrnDisregardApproved(orgMrn);
        if (org == null) {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
        if (org.isApproved()) {
            throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.ORG_ALREADY_APPROVED, request.getServletPath());
        }
        // Create the Identity Provider for the org
        if ("own-idp".equals(org.getFederationType()) && org.getIdentityProviderAttributes() != null && !org.getIdentityProviderAttributes().isEmpty()) {
            keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
            try {
                keycloakAU.createIdentityProvider(org.getMrn().toLowerCase(), org.getIdentityProviderAttributes());
            } catch (MalformedURLException e) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.INVALID_IDP_URL, request.getServletPath());
            } catch (IOException e) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.COULD_NOT_GET_DATA_FROM_IDP, request.getServletPath());
            }
        }
        // Enabled the organization and save it
        org.setApproved(true);
        Organization approvedOrg =  this.organizationService.save(org);
        return new ResponseEntity<>(approvedOrg, HttpStatus.OK);
    }


    /**
     * Returns info about the organization identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<Organization> getOrganization(HttpServletRequest request, @PathVariable String orgMrn) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org == null) {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
        return new ResponseEntity<>(org, HttpStatus.OK);
    }

    /**
     * Returns info about the organization identified by the given ID
     *
     * @return a reply
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/id/{orgId}",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8"
    )
    public ResponseEntity<Organization> getOrganizationById(HttpServletRequest request, @PathVariable Long orgId) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationById(orgId);
        if (org == null) {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
        return new ResponseEntity<>(org, HttpStatus.OK);
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
    public Page<Organization> getOrganization(Pageable pageable) {
        return this.organizationService.listAllPage(pageable);
    }

    /**
     * Updates info about the organization identified by the given ID
     * 
     * @return a http reply
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}",
            method = RequestMethod.PUT)
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> updateOrganization(HttpServletRequest request, @PathVariable String orgMrn,
            @Valid @RequestBody Organization input, BindingResult bindingResult) throws McBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            if (!orgMrn.equalsIgnoreCase(input.getMrn())) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
            }
            // If a well-known url and client id and secret was supplied, and it is different from the current data we create a new IDP, or update it.
            if ("own-idp".equals(input.getFederationType()) && input.getIdentityProviderAttributes() != null && !input.getIdentityProviderAttributes().isEmpty()) {
                keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                // If the IDP setup is different we delete the old IDP in keycloak
                if (org.getIdentityProviderAttributes() != null && !org.getIdentityProviderAttributes().isEmpty()
                        && !IdentityProviderAttribute.listsEquals(org.getIdentityProviderAttributes(), input.getIdentityProviderAttributes())) {
                    keycloakAU.deleteIdentityProvider(input.getMrn());
                }
                try {
                    keycloakAU.createIdentityProvider(input.getMrn().toLowerCase(), input.getIdentityProviderAttributes());
                } catch (InternalServerErrorException e) {
                    throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.INVALID_IDP_URL, request.getServletPath());
                } catch (IOException e) {
                    throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.COULD_NOT_GET_DATA_FROM_IDP, request.getServletPath());
                }
                org.setFederationType("own-idp");
            } else if (org.getIdentityProviderAttributes() != null && !org.getIdentityProviderAttributes().isEmpty()) {
                // Remove old IDP if new input doesn't contain IDP info
                keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                keycloakAU.deleteIdentityProvider(input.getMrn());
                // TODO: Determine if setting to "external-idp" could be done as well.
                org.setFederationType("test-idp");
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
            value = "/api/org/{orgMrn}",
            method = RequestMethod.DELETE)
    @PreAuthorize("hasRole('SITE_ADMIN')")
    public ResponseEntity<?> deleteOrg(HttpServletRequest request, @PathVariable String orgMrn) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrnDisregardApproved(orgMrn);
        if (org != null) {
            //  TODO: we need to do some sync'ing with the Service Registry.
            if (org.getIdentityProviderAttributes() != null && !org.getIdentityProviderAttributes().isEmpty()) {
                keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                keycloakAU.deleteIdentityProvider(org.getMrn());
            } else {
                for (User user : this.userService.listAllFromOrg(org.getId())) {
                    keycloakAU.deleteUser(user.getEmail(), user.getMrn());
                }
            }
            this.deviceService.deleteByOrg(org.getId());
            this.serviceService.deleteByOrg(org.getId());
            this.userService.deleteByOrg(org.getId());
            this.vesselService.deleteByOrg(org.getId());
            this.roleService.deleteByOrg(org.getId());
            this.mmsService.deleteByOrg(org.getId());
            this.organizationService.delete(org.getId());
            this.agentService.deleteByOrg(org.getId());
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
            value = "/api/org/{orgMrn}/certificate/issue-new",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<CertificateBundle> newOrgCert(HttpServletRequest request, @PathVariable String orgMrn) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            CertificateBundle ret = this.issueCertificate(org, org, "organization", request);
            return new ResponseEntity<>(ret, HttpStatus.OK);
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Takes a certificate signing request and returns a signed certificate with the public key from the csr
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/certificate/issue-new/csr",
            method = RequestMethod.POST,
            consumes = MediaType.TEXT_PLAIN_VALUE,
            produces = {"application/pem-certificate-chain", MediaType.APPLICATION_JSON_UTF8_VALUE}
    )
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<String> newOrgCertFromCsr(HttpServletRequest request, @PathVariable String orgMrn, @ApiParam(value = "A PEM encoded PKCS#10 CSR", required = true) @RequestBody String csr) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            JcaPKCS10CertificationRequest pkcs10CertificationRequest = CsrUtil.getCsrFromPem(request, csr);
            String cert = this.signCertificate(pkcs10CertificationRequest, org, org, "organization", request);
            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.setContentType(new MediaType("application", "pem-certificate-chain"));
            return new ResponseEntity<>(cert, httpHeaders, HttpStatus.OK);
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
            value = "/api/org/{orgMrn}/certificate/{certId}/revoke",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> revokeOrgCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable BigInteger certId, @Valid @RequestBody CertificateRevocation input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            Certificate cert = this.certificateService.getCertificateBySerialNumber(certId);
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

    @Override
    protected String getName(CertificateModel certOwner) {
        return ((Organization)certOwner).getName();
    }

    @Override
    protected String getUid(CertificateModel certOwner) {
        return ((Organization)certOwner).getMrn();
    }

    @Override
    protected String getEmail(CertificateModel certOwner) {
        return ((Organization)certOwner).getEmail();
    }

    @Override
    protected HashMap<String, String> getAttr(CertificateModel certOwner) {
        return null;
    }
}
