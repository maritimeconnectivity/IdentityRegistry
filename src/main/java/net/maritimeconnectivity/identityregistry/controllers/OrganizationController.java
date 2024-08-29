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
import net.maritimeconnectivity.identityregistry.exception.McpBasicRestException;
import net.maritimeconnectivity.identityregistry.model.data.CertificateRevocation;
import net.maritimeconnectivity.identityregistry.model.database.Certificate;
import net.maritimeconnectivity.identityregistry.model.database.CertificateModel;
import net.maritimeconnectivity.identityregistry.model.database.IdentityProviderAttribute;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.model.database.entities.Device;
import net.maritimeconnectivity.identityregistry.model.database.entities.MMS;
import net.maritimeconnectivity.identityregistry.model.database.entities.Service;
import net.maritimeconnectivity.identityregistry.model.database.entities.User;
import net.maritimeconnectivity.identityregistry.model.database.entities.Vessel;
import net.maritimeconnectivity.identityregistry.services.AgentService;
import net.maritimeconnectivity.identityregistry.services.EntityService;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import net.maritimeconnectivity.identityregistry.services.RoleService;
import net.maritimeconnectivity.identityregistry.utils.CsrUtil;
import net.maritimeconnectivity.identityregistry.utils.EmailUtil;
import net.maritimeconnectivity.identityregistry.utils.ExistsByMrnUtil;
import net.maritimeconnectivity.identityregistry.utils.KeycloakAdminUtil;
import net.maritimeconnectivity.identityregistry.utils.MCPIdRegConstants;
import net.maritimeconnectivity.identityregistry.utils.ValidateUtil;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springdoc.core.annotations.ParameterObject;
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
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.ws.rs.InternalServerErrorException;
import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;

@Slf4j
@RestController
public class OrganizationController extends BaseControllerWithCertificate {
    // These 5 services are used when deleting an organization
    private EntityService<Device> deviceService;
    private EntityService<Service> serviceService;
    private EntityService<User> userService;
    private EntityService<Vessel> vesselService;
    private EntityService<MMS> mmsService;

    private RoleService roleService;

    private EmailUtil emailUtil;

    private OrganizationService organizationService;

    private KeycloakAdminUtil keycloakAU;

    private AgentService agentService;

    private ExistsByMrnUtil existsByMrnUtil;

    /**
     * Receives an application for a new organization and root-user
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/apply",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Apply for getting your organization registered"
    )
    public ResponseEntity<Organization> applyOrganization(HttpServletRequest request, @RequestBody @Valid Organization input, BindingResult bindingResult) throws McpBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        // Make sure all mrn are lowercase
        input.setMrn(input.getMrn().trim().toLowerCase());
        if (!mrnUtil.isEntityTypeValid(input)) {
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, "The entity type in the MRN does not match the type of the entity being created.", request.getServletPath());
        }
        if (existsByMrnUtil.isMrnAlreadyUsed(input.getMrn())) {
            throw new McpBasicRestException(HttpStatus.CONFLICT, MCPIdRegConstants.ENTITY_WITH_MRN_ALREADY_EXISTS, request.getServletPath());
        }
        input.setApproved(false);
        // If no federation type is set we for now default to "test-idp"
        if (input.getFederationType() == null || input.getFederationType().isEmpty()) {
            input.setFederationType("test-idp");
        }
        // Default to the MC IDR CA
        input.setCertificateAuthority(certificateUtil.getDefaultSubCa());
        Organization newOrg = null;
        HttpHeaders headers = new HttpHeaders();
        try {
            newOrg = this.organizationService.save(input);
            String path = request.getRequestURL().toString().split("apply")[0] + URLEncoder.encode(newOrg.getMrn(), StandardCharsets.UTF_8);
            headers.setLocation(new URI(path));
        } catch (DataIntegrityViolationException e) {
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.ERROR_STORING_ENTITY, request.getServletPath());
        } catch (URISyntaxException e) {
            log.error("Could not create Location header", e);
        }
        if (newOrg == null) {
            log.error("Application for organization with MRN {} was not stored", input.getMrn());
            throw new McpBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCPIdRegConstants.ERROR_STORING_ENTITY, request.getServletPath());
        }
        // Send email to organization saying that the application is awaiting approval
        emailUtil.sendOrgAwaitingApprovalEmail(newOrg.getEmail(), newOrg.getName());
        // Send email to admin saying that an Organization is awaiting approval
        emailUtil.sendAdminOrgAwaitingApprovalEmail(newOrg.getName(), newOrg.getMrn());
        return new ResponseEntity<>(newOrg, headers, HttpStatus.CREATED);
    }

    /**
     * Returns list of all unapproved organizations
     *
     * @return a reply...
     */
    @GetMapping(
            value = "/api/org/unapprovedorgs",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get a page of organizations that have not yet been approved"
    )
    @PreAuthorize("hasRole('ROLE_APPROVE_ORG')")
    public Page<Organization> getUnapprovedOrganizations(@ParameterObject Pageable pageable) {
        return this.organizationService.getUnapprovedOrganizations(pageable);
    }

    /**
     * Approves the organization identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/approve",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Approve the given applying organization"
    )
    @PreAuthorize("hasRole('ROLE_APPROVE_ORG')")
    public ResponseEntity<Organization> approveOrganization(HttpServletRequest request, @PathVariable String orgMrn) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrnDisregardApproved(orgMrn);
        if (org == null) {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
        if (org.isApproved()) {
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.ORG_ALREADY_APPROVED, request.getServletPath());
        }
        // Create the Identity Provider for the org
        if ("own-idp".equals(org.getFederationType()) && org.getIdentityProviderAttributes() != null && !org.getIdentityProviderAttributes().isEmpty()) {
            keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
            try {
                keycloakAU.createIdentityProvider(org.getMrn().toLowerCase(), org.getIdentityProviderAttributes());
            } catch (MalformedURLException e) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.INVALID_IDP_URL, request.getServletPath());
            } catch (IOException e) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.COULD_NOT_GET_DATA_FROM_IDP, request.getServletPath());
            }
        }
        // Enabled the organization and save it
        org.setApproved(true);
        Organization approvedOrg;
        try {
            approvedOrg = this.organizationService.save(org);
        } catch (DataIntegrityViolationException e) {
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.ERROR_STORING_ENTITY, request.getServletPath());
        }

        return new ResponseEntity<>(approvedOrg, HttpStatus.OK);
    }


    /**
     * Returns info about the organization identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get a specific organization based on MRN"
    )
    public ResponseEntity<Organization> getOrganization(HttpServletRequest request, @PathVariable String orgMrn) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org == null) {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
        return new ResponseEntity<>(org, HttpStatus.OK);
    }

    /**
     * Returns info about the organization identified by the given ID
     *
     * @return a reply
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/id/{orgId}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get a specific organization based on ID"
    )
    public ResponseEntity<Organization> getOrganizationById(HttpServletRequest request, @PathVariable Long orgId) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationById(orgId);
        if (org == null) {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
        return new ResponseEntity<>(org, HttpStatus.OK);
    }

    /**
     * Returns list of all organizations
     *
     * @return a reply...
     */
    @GetMapping(
            value = "/api/orgs",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get a page of registered organizations"
    )
    public Page<Organization> getOrganization(@ParameterObject Pageable pageable) {
        return this.organizationService.listAllPage(pageable);
    }

    /**
     * Updates info about the organization identified by the given ID
     *
     * @return a http reply
     * @throws McpBasicRestException
     */
    @PutMapping(
            value = "/api/org/{orgMrn}"
    )
    @Operation(
            description = "Update a specific organization"
    )
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'ORG_ADMIN')")
    public ResponseEntity<?> updateOrganization(HttpServletRequest request, @PathVariable String orgMrn,
                                                @Valid @RequestBody Organization input, BindingResult bindingResult) throws McpBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            if (!orgMrn.equalsIgnoreCase(input.getMrn())) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
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
                    throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.INVALID_IDP_URL, request.getServletPath());
                } catch (IOException e) {
                    throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.COULD_NOT_GET_DATA_FROM_IDP, request.getServletPath());
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
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Deletes an Organization
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @DeleteMapping(
            value = "/api/org/{orgMrn}"
    )
    @Operation(
            description = "Delete a specific organization"
    )
    @PreAuthorize("hasRole('SITE_ADMIN')")
    public ResponseEntity<?> deleteOrg(HttpServletRequest request, @PathVariable String orgMrn) throws McpBasicRestException {
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
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    @GetMapping(
            value = "/api/org/{orgMrn}/certificate/{serialNumber}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get the organization certificate with the given serial number"
    )
    public ResponseEntity<Certificate> getOrgCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable BigInteger serialNumber) throws McpBasicRestException {
        Organization organization = this.organizationService.getOrganizationByMrn(orgMrn);
        if (organization != null) {
            Certificate certificate = this.certificateService.getCertificateBySerialNumber(serialNumber);
            if (certificate != null) {
                return new ResponseEntity<>(certificate, HttpStatus.OK);
            }
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.CERTIFICATE_NOT_FOUND, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Takes a certificate signing request and returns a signed certificate with the public key from the csr
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/{orgMrn}/certificate/issue-new/csr",
            consumes = {"application/x-pem-file", MediaType.TEXT_PLAIN_VALUE},
            produces = {"application/pem-certificate-chain", MediaType.APPLICATION_JSON_VALUE}
    )
    @Operation(
            description = "Create a new organization certificate using CSR",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "A PEM encoded PKCS#10 CSR")
    )
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'ORG_ADMIN')")
    public ResponseEntity<String> newOrgCertFromCsr(HttpServletRequest request, @PathVariable String orgMrn, @RequestBody String csr) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            JcaPKCS10CertificationRequest pkcs10CertificationRequest = CsrUtil.getCsrFromPem(request, csr);
            Certificate cert = this.signCertificate(pkcs10CertificationRequest, org, org, "organization", request);
            HttpHeaders httpHeaders = new HttpHeaders();
            String path = request.getRequestURL().toString().split("issue-new")[0] + cert.getSerialNumber().toString();
            try {
                httpHeaders.setLocation(new URI(path));
            } catch (URISyntaxException e) {
                log.error("Could not create Location header", e);
            }
            httpHeaders.setContentType(new MediaType("application", "pem-certificate-chain"));
            return new ResponseEntity<>(cert.getCertificate(), httpHeaders, HttpStatus.CREATED);
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Revokes certificate for the user identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/{orgMrn}/certificate/{certId}/revoke",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Revoke the organization certificate with the given serial number"
    )
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'ORG_ADMIN')")
    public ResponseEntity<?> revokeOrgCert(HttpServletRequest request, @PathVariable String orgMrn, @Parameter(description = "The serial number of the certificate given in decimal", required = true) @PathVariable BigInteger certId, @Valid @RequestBody CertificateRevocation input) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            Certificate cert = this.certificateService.getCertificateBySerialNumber(certId);
            Organization certOrg = cert.getOrganization();
            if (certOrg != null && certOrg.getId().compareTo(org.getId()) == 0) {
                this.revokeCertificate(certId, input, request);
                return new ResponseEntity<>(HttpStatus.OK);
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    @Override
    protected String getName(CertificateModel certOwner) {
        return ((Organization) certOwner).getName();
    }

    @Override
    protected String getUid(CertificateModel certOwner) {
        return ((Organization) certOwner).getMrn();
    }

    @Override
    protected String getEmail(CertificateModel certOwner) {
        return ((Organization) certOwner).getEmail();
    }

    @Override
    protected HashMap<String, String> getAttr(CertificateModel certOwner) {
        return new HashMap<>();
    }

    @Autowired
    public void setDeviceService(EntityService<Device> deviceService) {
        this.deviceService = deviceService;
    }

    @Autowired
    public void setServiceService(EntityService<Service> serviceService) {
        this.serviceService = serviceService;
    }

    @Autowired
    public void setUserService(EntityService<User> userService) {
        this.userService = userService;
    }

    @Autowired
    public void setVesselService(EntityService<Vessel> vesselService) {
        this.vesselService = vesselService;
    }

    @Autowired
    public void setMmsService(EntityService<MMS> mmsService) {
        this.mmsService = mmsService;
    }

    @Autowired
    public void setRoleService(RoleService roleService) {
        this.roleService = roleService;
    }

    @Autowired
    public void setEmailUtil(EmailUtil emailUtil) {
        this.emailUtil = emailUtil;
    }

    @Autowired
    public void setOrganizationService(OrganizationService organizationService) {
        this.organizationService = organizationService;
    }

    @Autowired
    public void setKeycloakAU(KeycloakAdminUtil keycloakAU) {
        this.keycloakAU = keycloakAU;
    }

    @Autowired
    public void setAgentService(AgentService agentService) {
        this.agentService = agentService;
    }

    @Autowired
    public void setExistsByMrnUtil(ExistsByMrnUtil existsByMrnUtil) {
        this.existsByMrnUtil = existsByMrnUtil;
    }
}
