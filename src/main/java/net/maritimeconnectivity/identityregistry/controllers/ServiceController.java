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
import net.maritimeconnectivity.identityregistry.model.data.CertificateRevocation;
import net.maritimeconnectivity.identityregistry.model.data.ServicePatch;
import net.maritimeconnectivity.identityregistry.model.database.Certificate;
import net.maritimeconnectivity.identityregistry.model.database.CertificateModel;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.model.database.entities.Service;
import net.maritimeconnectivity.identityregistry.model.database.entities.Vessel;
import net.maritimeconnectivity.identityregistry.services.EntityService;
import net.maritimeconnectivity.identityregistry.services.ServiceService;
import net.maritimeconnectivity.identityregistry.services.VesselServiceImpl;
import net.maritimeconnectivity.identityregistry.utils.AttributesUtil;
import net.maritimeconnectivity.identityregistry.utils.KeycloakAdminUtil;
import net.maritimeconnectivity.identityregistry.utils.MCPIdRegConstants;
import net.maritimeconnectivity.identityregistry.utils.ValidateUtil;
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
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.regex.Pattern;

@RestController
@Slf4j
public class ServiceController extends EntityController<Service> {
    private KeycloakAdminUtil keycloakAU;

    private VesselServiceImpl vesselService;

    private static final String TYPE = "service";

    /**
     * Creates a new Service
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/{orgMrn}/service",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Create a new service identity"
    )
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'SERVICE_ADMIN')")
    public ResponseEntity<Service> createService(HttpServletRequest request, @PathVariable String orgMrn, @Valid @RequestBody Service input, BindingResult bindingResult) throws McpBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        Organization org = this.organizationService.getOrganizationByMrnNoFilter(orgMrn);
        if (org != null) {
            // Check that the entity being created belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(input.getMrn()))) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            if (existsByMrnUtil.isMrnAlreadyUsed(input.getMrn())) {
                throw new McpBasicRestException(HttpStatus.CONFLICT, MCPIdRegConstants.ENTITY_WITH_MRN_ALREADY_EXISTS, request.getServletPath());
            }
            input.setIdOrganization(org.getId());
            if (input.getInstanceVersion() != null && !input.getInstanceVersion().isBlank()) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.INSTANCE_VERSION_NOT_ALLOWED, request.getServletPath());
            }
            input.setMrn(input.getMrn().toLowerCase());
            // If the service requested to be created contains a vessel, add it to the service
            this.addVesselToServiceIfPresent(input, orgMrn, request);
            // Setup a keycloak client for the service if needed
            if (input.getOidcAccessType() != null && !input.getOidcAccessType().trim().isEmpty()) {
                // Check if the redirect uri is set if access type is not "bearer-only"
                if (!"bearer-only".equals(input.getOidcAccessType()) && (input.getOidcRedirectUri() == null || input.getOidcRedirectUri().trim().isEmpty())) {
                    throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.OIDC_MISSING_REDIRECT_URL, request.getServletPath());
                }
                keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                input.generateOidcClientId();
                try {
                    String clientSecret = keycloakAU.createClient(input.getOidcClientId(), input.getOidcAccessType(), input.getOidcRedirectUri());
                    if ("confidential".equals(input.getOidcAccessType())) {
                        input.setOidcClientSecret(clientSecret);
                    } else {
                        input.setOidcClientSecret(null);
                    }
                } catch (IOException e) {
                    throw new McpBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCPIdRegConstants.ERROR_CREATING_KC_CLIENT, request.getServletPath());
                } catch (DuplicatedKeycloakEntry dke) {
                    throw new McpBasicRestException(HttpStatus.CONFLICT, dke.getErrorMessage(), request.getServletPath());
                }
            } else {
                input.setOidcAccessType(null);
                input.setOidcClientId(null);
                input.setOidcClientSecret(null);
                input.setOidcRedirectUri(null);
            }
            Service newService = null;
            HttpHeaders headers = new HttpHeaders();
            try {
                newService = this.entityService.save(input);
                String path = request.getRequestURL().append("/").append(URLEncoder.encode(newService.getMrn(), StandardCharsets.UTF_8)).toString();
                headers.setLocation(new URI(path));
            } catch (DataIntegrityViolationException e) {
                // If save to DB failed, remove the client from keycloak if it was created.
                if (input.getOidcAccessType() != null && !input.getOidcAccessType().trim().isEmpty()) {
                    keycloakAU.deleteClient(input.getOidcClientId());
                }
                log.error("Service could not be stored in database.", e);
                throw new McpBasicRestException(HttpStatus.CONFLICT, MCPIdRegConstants.ERROR_STORING_ENTITY, request.getServletPath());
            } catch (URISyntaxException e) {
                log.error("Could not create Location header", e);
            }
            return new ResponseEntity<>(newService, headers, HttpStatus.CREATED);
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns all version of the service instance identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/services/{serviceMrn}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get a page of service identities with a given MRN prefix"
    )
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn, null)")
    public Page<Service> getServices(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, Pageable pageable) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Page<Service> services = ((ServiceService) this.entityService).getServicesByMrn(serviceMrn, pageable);
            if (services == null || !services.hasContent()) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (services.iterator().next().getIdOrganization().equals(org.getId())) {
                return services;
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * @param request    the HTTP request
     * @param orgMrn     the org MRN
     * @param serviceMrn the service MRN
     * @return a response containing a service
     * @throws McpBasicRestException if something goes wrong
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get the service identity with the given MRN. If a direct match cannot be found, the service " +
                    "that was last created and has the given MRN as a prefix of its MRN followed by an additional namespace will be returned."
    )
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn, null)")
    public ResponseEntity<Service> getService(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }

            // Start by checking whether we have a direct match on the MRN
            Service service = entityService.getByMrn(serviceMrn);
            if (service != null) {
                return ResponseEntity.ok(service);
            }

            // Else, check if there are any services that have the MRN as prefix of their MRN and return the latest that was created
            service = ((ServiceService) entityService).getNewestServiceByMrn(serviceMrn);
            if (service == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().equals(org.getId())) {
                return new ResponseEntity<>(service, HttpStatus.OK);
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns specific version of the service instance identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     * @deprecated will be removed in the future as version is no longer kept separate from MRN
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/{version}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get the service identity with the given MRN and version",
            deprecated = true
    )
    @Deprecated(forRemoval = true)
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn, null)")
    public ResponseEntity<Service> getServiceVersion(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @PathVariable String version) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = ((ServiceService) this.entityService).getServiceByMrnAndVersion(serviceMrn, version);
            if (service == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().equals(org.getId())) {
                return new ResponseEntity<>(service, HttpStatus.OK);
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Updates a Service
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PutMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}"
    )
    @Operation(
            description = "Update a specific service identity"
    )
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'SERVICE_ADMIN')")
    public ResponseEntity<?> updateService(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @Valid @RequestBody Service input, BindingResult bindingResult) throws McpBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        if (!serviceMrn.equalsIgnoreCase(input.getMrn())) {
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
        }
        Organization org = this.organizationService.getOrganizationByMrnNoFilter(orgMrn);
        if (org != null) {
            // Check that the entity being updated belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(input.getMrn()))) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = this.entityService.getByMrn(serviceMrn);
            if (service == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().equals(org.getId())) {
                if (input.getInstanceVersion() != null && !input.getInstanceVersion().isEmpty()) {
                    throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.INSTANCE_VERSION_NOT_ALLOWED, request.getServletPath());
                }

                // Update the keycloak client for the service if needed
                if (input.getOidcAccessType() != null && !input.getOidcAccessType().trim().isEmpty()) {
                    // Check if the redirect uri is set if access type is not "bearer-only"
                    if (!"bearer-only".equals(input.getOidcAccessType()) && (input.getOidcRedirectUri() == null || input.getOidcRedirectUri().trim().isEmpty())) {
                        throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.OIDC_MISSING_REDIRECT_URL, request.getServletPath());
                    }
                    keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                    String clientSecret;
                    try {
                        if (service.getOidcClientId() != null && !service.getOidcClientId().isEmpty()) {
                            clientSecret = keycloakAU.updateClient(service.getOidcClientId(), input.getOidcAccessType(), input.getOidcRedirectUri());
                        } else {
                            service.generateOidcClientId();
                            clientSecret = keycloakAU.createClient(service.getOidcClientId(), input.getOidcAccessType(), input.getOidcRedirectUri());
                        }
                    } catch (IOException e) {
                        log.error("Error while updating/creating client in keycloak.", e);
                        throw new McpBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCPIdRegConstants.ERROR_CREATING_KC_CLIENT, request.getServletPath());
                    } catch (DuplicatedKeycloakEntry dke) {
                        throw new McpBasicRestException(HttpStatus.CONFLICT, dke.getErrorMessage(), request.getServletPath());
                    }
                    if ("confidential".equals(input.getOidcAccessType())) {
                        service.setOidcClientSecret(clientSecret);
                    } else {
                        service.setOidcClientSecret(null);
                    }
                } else if (service.getOidcAccessType() != null && !service.getOidcAccessType().trim().isEmpty()) {
                    // Delete the keycloak client since the updated service does not use it
                    keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                    keycloakAU.deleteClient(service.getOidcClientId());
                    service.setOidcAccessType(null);
                    service.setOidcClientId(null);
                    service.setOidcClientSecret(null);
                    service.setOidcRedirectUri(null);
                }
                this.addVesselToServiceIfPresent(input, orgMrn, request);
                input.selectiveCopyTo(service);
                try {
                    this.entityService.save(service);
                    return new ResponseEntity<>(HttpStatus.OK);
                } catch (DataIntegrityViolationException e) {
                    throw new McpBasicRestException(HttpStatus.CONFLICT, MCPIdRegConstants.ERROR_STORING_ENTITY, request.getServletPath());
                }
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Updates a Service
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PutMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/{version}"
    )
    @Operation(
            description = "DEPRECATED: A service with a version cannot be updated until it has been migrated using the endpoint at /api/org/{orgMrn}/service/{serviceMrn}/{version}/migrate.\n" +
                    "This endpoint will return an error if called.",
            deprecated = true
    )
    @Deprecated(forRemoval = true)
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'SERVICE_ADMIN')")
    public ResponseEntity<?> updateService(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @PathVariable String version, @Valid @RequestBody Service input, BindingResult bindingResult) throws McpBasicRestException {
        throw new McpBasicRestException(HttpStatus.METHOD_NOT_ALLOWED, "A Service with a version must be migrated before it can be updated.", request.getServletPath());
    }

    /**
     * Deletes a Service
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @DeleteMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}"
    )
    @Operation(
            description = "Delete a specific service identity"
    )
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'SERVICE_ADMIN')")
    public ResponseEntity<?> deleteService(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrnNoFilter(orgMrn);
        if (org != null) {
            // Check that the entity being deleted belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = this.entityService.getByMrn(serviceMrn);
            if (service == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().equals(org.getId())) {
                // Delete the keycloak client for the service if needed
                if (service.getOidcClientId() != null && !service.getOidcClientId().trim().isEmpty()) {
                    keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                    keycloakAU.deleteClient(service.getOidcClientId());
                }
                this.entityService.delete(service.getId());
                return new ResponseEntity<>(HttpStatus.OK);
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Deletes a Service
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @DeleteMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/{version}"
    )
    @Operation(
            description = "Delete a specific service identity",
            deprecated = true
    )
    @Deprecated(forRemoval = true)
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'SERVICE_ADMIN')")
    public ResponseEntity<?> deleteService(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @PathVariable String version) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrnNoFilter(orgMrn);
        if (org != null) {
            // Check that the entity being deleted belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = ((ServiceService) this.entityService).getServiceByMrnAndVersion(serviceMrn, version);
            if (service == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().equals(org.getId())) {
                // Delete the keycloak client for the service if needed
                if (service.getOidcClientId() != null && !service.getOidcClientId().trim().isEmpty()) {
                    keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                    keycloakAU.deleteClient(service.getOidcClientId());
                }
                this.entityService.delete(service.getId());
                return new ResponseEntity<>(HttpStatus.OK);
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns a list of services owned by the organization identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/services",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get a page of service identities of the specified organization"
    )
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn, null)")
    public Page<Service> getOrganizationServices(HttpServletRequest request, @PathVariable String orgMrn, @ParameterObject Pageable pageable) throws McpBasicRestException {
        return this.getOrganizationEntities(request, orgMrn, pageable);
    }

    @GetMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/certificate/{serialNumber}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get the service identity certificate with the given serial number"
    )
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn, null)")
    public ResponseEntity<Certificate> getServiceCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @PathVariable BigInteger serialNumber) throws McpBasicRestException {
        return this.getEntityCert(request, orgMrn, serviceMrn, TYPE, null, serialNumber);
    }

    @GetMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/{version}/certificate/{serialNumber}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get the service identity certificate with the given serial number",
            deprecated = true
    )
    @Deprecated(forRemoval = true)
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn, null)")
    public ResponseEntity<Certificate> getServiceCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @PathVariable String version, @PathVariable BigInteger serialNumber) throws McpBasicRestException {
        return this.getEntityCert(request, orgMrn, serviceMrn, TYPE, version, serialNumber);
    }

    /**
     * Takes a certificate signing request and returns a signed certificate with the public key from the csr
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/certificate/issue-new/csr",
            consumes = {"application/x-pem-file", MediaType.TEXT_PLAIN_VALUE},
            produces = {"application/pem-certificate-chain", MediaType.APPLICATION_JSON_VALUE}
    )
    @Operation(
            description = "Create a new service identity certificate using CSR",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "A PEM encoded PKCS#10 CSR")
    )
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'SERVICE_ADMIN')")
    public ResponseEntity<String> newServiceCertFromCsr(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @RequestBody String csr) throws McpBasicRestException {
        return this.signEntityCert(request, csr, orgMrn, serviceMrn, TYPE);
    }

    /**
     * Takes a certificate signing request and returns a signed certificate with the public key from the csr
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/{version}/certificate/issue-new/csr",
            consumes = {"application/x-pem-file", MediaType.TEXT_PLAIN_VALUE},
            produces = {"application/pem-certificate-chain", MediaType.APPLICATION_JSON_VALUE}
    )
    @Operation(
            description = "DEPRECATED: Certificates cannot be issued for a service with a version until it has been migrated using the the endpoint at /api/org/{orgMrn}/service/{serviceMrn}/{version}/migrate.\n" +
                    "This endpoint will return an error if called.",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "A PEM encoded PKCS#10 CSR"),
            deprecated = true
    )
    @Deprecated(forRemoval = true)
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'SERVICE_ADMIN')")
    public ResponseEntity<String> newServiceCertFromCsr(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @PathVariable String version, @RequestBody String csr) throws McpBasicRestException {
        throw new McpBasicRestException(HttpStatus.METHOD_NOT_ALLOWED, "Service must be migrated before certificates can be issued for it.", request.getServletPath());
    }

    /**
     * Revokes certificate for the service identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/certificate/{certId}/revoke",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Revoke the service identity certificate with the given serial number"
    )
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'SERVICE_ADMIN')")
    public ResponseEntity<?> revokeServiceCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @Parameter(description = "The serial number of the certificate given in decimal", required = true) @PathVariable BigInteger certId, @Valid @RequestBody CertificateRevocation input) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrnNoFilter(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = this.entityService.getByMrn(serviceMrn);
            if (service == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().equals(org.getId())) {
                Certificate cert = this.certificateService.getCertificateBySerialNumber(certId);
                Service certEntity = getCertEntity(cert);
                if (certEntity != null && certEntity.getId().equals(service.getId())) {
                    this.revokeCertificate(cert.getSerialNumber(), input, request);
                    return new ResponseEntity<>(HttpStatus.OK);
                }
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Revokes certificate for the service identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/{version}/certificate/{certId}/revoke",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Revoke the service identity certificate with the given serial number",
            deprecated = true
    )
    @Deprecated(forRemoval = true)
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'SERVICE_ADMIN')")
    public ResponseEntity<?> revokeServiceCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @PathVariable String version, @Parameter(description = "The serial number of the certificate given in decimal", required = true) @PathVariable BigInteger certId, @Valid @RequestBody CertificateRevocation input) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrnNoFilter(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = ((ServiceService) this.entityService).getServiceByMrnAndVersion(serviceMrn, version);
            if (service == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().equals(org.getId())) {
                Certificate cert = this.certificateService.getCertificateBySerialNumber(certId);
                Service certEntity = getCertEntity(cert);
                if (certEntity != null && certEntity.getId().equals(service.getId())) {
                    this.revokeCertificate(cert.getSerialNumber(), input, request);
                    return new ResponseEntity<>(HttpStatus.OK);
                }
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns keycloak.json the service identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/keycloakjson",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get the Keycloak JSON configuration for the specified service if it exists"
    )
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'SERVICE_ADMIN')")
    public ResponseEntity<String> getServiceKeycloakJson(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = this.entityService.getByMrn(serviceMrn);
            if (service == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().equals(org.getId())) {
                // Get the keycloak json for the client the service represents if it exists
                if (service.getOidcAccessType() != null && !service.getOidcAccessType().trim().isEmpty()) {
                    keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                    try {
                        String keycloakJson = keycloakAU.getClientKeycloakJson(service.getOidcClientId());
                        return new ResponseEntity<>(keycloakJson, HttpStatus.OK);
                    } catch (IOException e) {
                        log.error("Getting keycloak JSON configuration for service failed", e);
                        throw new McpBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCPIdRegConstants.SOMETHING_WENT_WRONG, request.getServletPath());
                    }
                }
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.OIDC_CONF_FILE_NOT_AVAILABLE, request.getServletPath());
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns keycloak.json the service identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/{version}/keycloakjson",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get the Keycloak JSON configuration for the specified service if it exists",
            deprecated = true
    )
    @Deprecated(forRemoval = true)
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'SERVICE_ADMIN')")
    public ResponseEntity<String> getServiceKeycloakJson(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @PathVariable String version) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = ((ServiceService) this.entityService).getServiceByMrnAndVersion(serviceMrn, version);
            if (service == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().equals(org.getId())) {
                // Get the keycloak json for the client the service represents if it exists
                if (service.getOidcAccessType() != null && !service.getOidcAccessType().trim().isEmpty()) {
                    keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                    try {
                        String keycloakJson = keycloakAU.getClientKeycloakJson(service.getOidcClientId());
                        return new ResponseEntity<>(keycloakJson, HttpStatus.OK);
                    } catch (IOException e) {
                        log.error("Getting keycloak JSON configuration for service failed", e);
                        throw new McpBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCPIdRegConstants.SOMETHING_WENT_WRONG, request.getServletPath());
                    }
                }
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.OIDC_CONF_FILE_NOT_AVAILABLE, request.getServletPath());
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns keycloak.json the service identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/jbossxml"
    )
    @Operation(
            description = "Get the Keycloak JBoss XML configuration for the specified service if it exists"
    )
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'SERVICE_ADMIN')")
    public ResponseEntity<String> getServiceJbossXml(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = this.entityService.getByMrn(serviceMrn);
            if (service == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().equals(org.getId())) {
                // Get the jboss xml for the client the service represents if it exists
                if (service.getOidcAccessType() != null && !service.getOidcAccessType().trim().isEmpty()) {
                    keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                    try {
                        String jbossXml = keycloakAU.getClientJbossXml(service.getOidcClientId());
                        HttpHeaders responseHeaders = new HttpHeaders();
                        responseHeaders.setContentLength(jbossXml.length());
                        responseHeaders.setContentType(MediaType.APPLICATION_XML);
                        return new ResponseEntity<>(jbossXml, responseHeaders, HttpStatus.OK);
                    } catch (IOException e) {
                        log.error("Getting keycloak XML configuration for service failed", e);
                        throw new McpBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCPIdRegConstants.SOMETHING_WENT_WRONG, request.getServletPath());
                    }
                }
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.OIDC_CONF_FILE_NOT_AVAILABLE, request.getServletPath());
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns keycloak.json the service identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/{version}/jbossxml"
    )
    @Operation(
            description = "Get the Keycloak JBoss XML configuration for the specified service if it exists",
            deprecated = true
    )
    @Deprecated(forRemoval = true)
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'SERVICE_ADMIN')")
    public ResponseEntity<String> getServiceJbossXml(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @PathVariable String version) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = ((ServiceService) this.entityService).getServiceByMrnAndVersion(serviceMrn, version);
            if (service == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().equals(org.getId())) {
                // Get the jboss xml for the client the service represents if it exists
                if (service.getOidcAccessType() != null && !service.getOidcAccessType().trim().isEmpty()) {
                    keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                    try {
                        String jbossXml = keycloakAU.getClientJbossXml(service.getOidcClientId());
                        HttpHeaders responseHeaders = new HttpHeaders();
                        responseHeaders.setContentLength(jbossXml.length());
                        responseHeaders.setContentType(MediaType.APPLICATION_XML);
                        return new ResponseEntity<>(jbossXml, responseHeaders, HttpStatus.OK);
                    } catch (IOException e) {
                        log.error("Getting keycloak XML configuration for service failed", e);
                        throw new McpBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCPIdRegConstants.SOMETHING_WENT_WRONG, request.getServletPath());
                    }
                }
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.OIDC_CONF_FILE_NOT_AVAILABLE, request.getServletPath());
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    @PatchMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/{version}/migrate",
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Update the MRN of a Service entity that currently has an instance version registered and delete the instance version entirely. " +
                    "Note that if the new MRN is different from the current MRN of the Service this operation will revoke all certificates that are currently associated with the Service entity. " +
                    "Also note that the result of performing this operation cannot be reverted."
    )
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'SERVICE_ADMIN')")
    public ResponseEntity<?> migrateServiceMrn(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @PathVariable String version, @Valid @RequestBody ServicePatch servicePatch) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            String orgShortName = mrnUtil.getOrgShortNameFromOrgMrn(orgMrn);
            // Check that the entity being queried belongs to the organization
            if (!orgShortName.equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = ((ServiceService) this.entityService).getServiceByMrnAndVersion(serviceMrn, version);
            if (service == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().equals(org.getId()) && orgShortName.equals(mrnUtil.getOrgShortNameFromEntityMrn(servicePatch.getMrn()))) {
                if (((ServiceService) this.entityService).getServiceByMrnAndVersion(servicePatch.getMrn(), null) != null || this.existsByMrnUtil.isMrnAlreadyUsed(servicePatch.getMrn())) {
                    throw new McpBasicRestException(HttpStatus.CONFLICT, MCPIdRegConstants.ENTITY_WITH_MRN_ALREADY_EXISTS, request.getServletPath());
                }
                String oldMrn = servicePatch.getMrn();
                service.setMrn(servicePatch.getMrn());
                service.setInstanceVersion(null);
                if (!servicePatch.getMrn().equals(oldMrn)) {
                    service.revokeAllCertificates();
                }
                entityService.save(service);

                HttpHeaders responseHeaders = new HttpHeaders();
                try {
                    String location = request.getRequestURL().toString().split(Pattern.quote("/" + serviceMrn))[0] + "/" + servicePatch.getMrn();
                    responseHeaders.setLocation(new URI(location));
                } catch (Exception e) {
                    log.error("Could not create Location header", e);
                }
                return new ResponseEntity<>(responseHeaders, HttpStatus.NO_CONTENT);
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    @Override
    protected Service getCertEntity(Certificate cert) {
        return cert.getService();
    }

    @Override
    protected String getName(CertificateModel certOwner) {
        String name = ((Service) certOwner).getCertDomainName();
        if (name == null || name.trim().isEmpty()) {
            name = ((Service) certOwner).getName();
        } else {
            // Make sure that we only put one domain name in the common name field
            String[] domainNames = name.split(",");
            name = domainNames[0].trim();
        }
        return name;
    }

    private void addVesselToServiceIfPresent(Service input, String orgMrn, HttpServletRequest request) throws McpBasicRestException {
        if (input.getVessel() != null) {
            String vesselMrn = input.getVessel().getMrn();
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(vesselMrn))) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Vessel vessel = this.vesselService.getByMrn(vesselMrn);
            input.setVessel(vessel);
        }
    }

    @Override
    protected HashMap<String, String> getAttr(CertificateModel certOwner) {
        HashMap<String, String> attrs = super.getAttr(certOwner);
        // Find special MC attributes to put in the certificate
        attrs.putAll(AttributesUtil.getAttributes(certOwner));

        return attrs;
    }

    @Autowired
    public void setKeycloakAU(KeycloakAdminUtil keycloakAU) {
        this.keycloakAU = keycloakAU;
    }

    @Autowired
    public void setVesselService(VesselServiceImpl vesselService) {
        this.vesselService = vesselService;
    }

    @Autowired
    public void setEntityService(EntityService<Service> entityService) {
        this.entityService = entityService;
    }
}
