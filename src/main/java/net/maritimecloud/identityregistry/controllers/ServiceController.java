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

import lombok.extern.slf4j.Slf4j;
import net.maritimecloud.identityregistry.exception.DuplicatedKeycloakEntry;
import net.maritimecloud.identityregistry.exception.McBasicRestException;
import net.maritimecloud.identityregistry.model.data.CertificateRevocation;
import net.maritimecloud.identityregistry.model.data.PemCertificate;
import net.maritimecloud.identityregistry.model.database.Certificate;
import net.maritimecloud.identityregistry.model.database.CertificateModel;
import net.maritimecloud.identityregistry.model.database.Organization;
import net.maritimecloud.identityregistry.model.database.entities.Service;
import net.maritimecloud.identityregistry.services.EntityService;
import net.maritimecloud.identityregistry.services.ServiceService;
import net.maritimecloud.identityregistry.utils.KeycloakAdminUtil;
import net.maritimecloud.identityregistry.utils.MCIdRegConstants;
import net.maritimecloud.identityregistry.utils.MrnUtil;
import net.maritimecloud.identityregistry.utils.ValidateUtil;
import net.maritimecloud.pki.PKIConstants;
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
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;

@RestController
@Slf4j
public class ServiceController extends EntityController<Service> {
    @Autowired
    private KeycloakAdminUtil keycloakAU;

    @Autowired
    public void setEntityService(EntityService<Service> entityService) {
        this.entityService = entityService;
    }


    /**
     * Creates a new Service
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */ 
    @RequestMapping(
            value = "/api/org/{orgMrn}/service",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<Service> createService(HttpServletRequest request, @PathVariable String orgMrn, @Valid @RequestBody Service input, BindingResult bindingResult) throws McBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being created belongs to the organization
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(MrnUtil.getOrgShortNameFromEntityMrn(input.getMrn()))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            input.setIdOrganization(org.getId());
            input.setMrn(input.getMrn().toLowerCase());
            // Setup a keycloak client for the service if needed
            if (input.getOidcAccessType() != null && !input.getOidcAccessType().trim().isEmpty()) {
                // Check if the redirect uri is set if access type is not "bearer-only"
                if (!"bearer-only".equals(input.getOidcAccessType()) && (input.getOidcRedirectUri() == null || input.getOidcRedirectUri().trim().isEmpty())) {
                    throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.OIDC_MISSING_REDIRECT_URL, request.getServletPath());
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
                } catch(IOException e) {
                    throw new McBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCIdRegConstants.ERROR_CREATING_KC_CLIENT, request.getServletPath());
                } catch (DuplicatedKeycloakEntry dke) {
                    throw new McBasicRestException(HttpStatus.CONFLICT, dke.getErrorMessage(), request.getServletPath());
                }
            } else {
                input.setOidcAccessType(null);
                input.setOidcClientId(null);
                input.setOidcClientSecret(null);
                input.setOidcRedirectUri(null);
            }
            try {
                Service newService = this.entityService.save(input);
                return new ResponseEntity<>(newService, HttpStatus.OK);
            } catch (DataIntegrityViolationException e) {
                // If save to DB failed, remove the client from keycloak if it was created.
                if (input.getOidcAccessType() != null && !input.getOidcAccessType().trim().isEmpty()) {
                    keycloakAU.deleteClient(input.getOidcClientId());
                }
                throw new McBasicRestException(HttpStatus.CONFLICT, e.getRootCause().getMessage(), request.getServletPath());
            }
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns all version of the service instance identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn)")
    public Page<Service> getService(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, Pageable pageable) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(MrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Page<Service> services = ((ServiceService) this.entityService).getServicesByMrn(serviceMrn, pageable);
            if (services == null || !services.hasContent()) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (services.iterator().next().getIdOrganization().compareTo(org.getId()) == 0) {
                return services;
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns specific version of the service instance identified by the given ID
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/{version}",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<Service> getServiceVersion(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @PathVariable String version) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(MrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = ((ServiceService) this.entityService).getServiceByMrnAndVersion(serviceMrn, version);
            if (service == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().compareTo(org.getId()) == 0) {
                return new ResponseEntity<>(service, HttpStatus.OK);
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Updates a Service
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/{version}",
            method = RequestMethod.PUT)
    @ResponseBody
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> updateService(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @PathVariable String version, @Valid @RequestBody Service input, BindingResult bindingResult) throws McBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        if (!serviceMrn.equalsIgnoreCase(input.getMrn()) || !version.equals(input.getInstanceVersion())) {
            throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
        }
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being updated belongs to the organization
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(MrnUtil.getOrgShortNameFromEntityMrn(input.getMrn()))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = ((ServiceService) this.entityService).getServiceByMrnAndVersion(serviceMrn, version);
            if (service == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().compareTo(org.getId()) == 0) {
                // Update the keycloak client for the service if needed
                if (input.getOidcAccessType() != null && !input.getOidcAccessType().trim().isEmpty()) {
                    // Check if the redirect uri is set if access type is not "bearer-only"
                    if (!"bearer-only".equals(input.getOidcAccessType()) && (input.getOidcRedirectUri() == null || input.getOidcRedirectUri().trim().isEmpty())) {
                        throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.OIDC_MISSING_REDIRECT_URL, request.getServletPath());
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
                    } catch (IOException e){
                        log.error("Error while updating/creation client in keycloak.", e);
                        throw new McBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCIdRegConstants.ERROR_CREATING_KC_CLIENT, request.getServletPath());
                    } catch (DuplicatedKeycloakEntry dke) {
                        throw new McBasicRestException(HttpStatus.CONFLICT, dke.getErrorMessage(), request.getServletPath());
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
                input.selectiveCopyTo(service);
                try {
                    this.entityService.save(service);
                    return new ResponseEntity<>(HttpStatus.OK);
                } catch (DataIntegrityViolationException e) {
                    throw new McBasicRestException(HttpStatus.CONFLICT, e.getRootCause().getMessage(), request.getServletPath());
                }
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Deletes a Service
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/{version}",
            method = RequestMethod.DELETE)
    @ResponseBody
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> deleteService(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @PathVariable String version) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being deleted belongs to the organization
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(MrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = ((ServiceService) this.entityService).getServiceByMrnAndVersion(serviceMrn, version);
            if (service == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().compareTo(org.getId()) == 0) {
                // Delete the keycloak client for the service if needed
                if (service.getOidcClientId() != null && !service.getOidcClientId().trim().isEmpty()) {
                    keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                    keycloakAU.deleteClient(service.getOidcClientId());
                }
                this.entityService.delete(service.getId());
                return new ResponseEntity<>(HttpStatus.OK);
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns a list of services owned by the organization identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/services",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn)")
    public Page<Service> getOrganizationServices(HttpServletRequest request, @PathVariable String orgMrn, Pageable pageable) throws McBasicRestException {
        return this.getOrganizationEntities(request, orgMrn, pageable);
    }

    /**
     * Returns new certificate for the service identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/{version}/certificate/issue-new",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<PemCertificate> newServiceCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @PathVariable String version) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(MrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = ((ServiceService) this.entityService).getServiceByMrnAndVersion(serviceMrn, version);
            if (service == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().compareTo(org.getId()) == 0) {
                PemCertificate ret = this.issueCertificate(service, org, "service", request);
                return new ResponseEntity<>(ret, HttpStatus.OK);
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Revokes certificate for the service identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/{version}/certificate/{certId}/revoke",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> revokeServiceCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @PathVariable String version, @PathVariable BigInteger certId, @Valid @RequestBody CertificateRevocation input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(MrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = ((ServiceService) this.entityService).getServiceByMrnAndVersion(serviceMrn, version);
            if (service == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().compareTo(org.getId()) == 0) {
                Certificate cert = this.certificateService.getCertificateBySerialNumber(certId);
                Service certEntity = getCertEntity(cert);
                if (certEntity != null && certEntity.getId().compareTo(service.getId()) == 0) {
                    this.revokeCertificate(cert.getSerialNumber(), input, request);
                    return new ResponseEntity<>(HttpStatus.OK);
                }
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns keycloak.json the service identified by the given ID
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/{version}/keycloakjson",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<String> getServiceKeycloakJson(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @PathVariable String version) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(MrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = ((ServiceService) this.entityService).getServiceByMrnAndVersion(serviceMrn, version);
            if (service == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().compareTo(org.getId()) == 0) {
                // Get the keycloak json for the client the service represents if it exists
                if (service.getOidcAccessType() != null && !service.getOidcAccessType().trim().isEmpty()) {
                    keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                    String keycloakJson = keycloakAU.getClientKeycloakJson(service.getOidcClientId());
                    return new ResponseEntity<>(keycloakJson, HttpStatus.OK);
                }
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.OIDC_CONF_FILE_NOT_AVAILABLE, request.getServletPath());
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns keycloak.json the service identified by the given ID
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/{version}/jbossxml",
            method = RequestMethod.GET)
    @ResponseBody
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<String> getServiceJbossXml(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @PathVariable String version) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(MrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = ((ServiceService) this.entityService).getServiceByMrnAndVersion(serviceMrn, version);
            if (service == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().compareTo(org.getId()) == 0) {
                // Get the jboss xml for the client the service represents if it exists
                if (service.getOidcAccessType() != null && !service.getOidcAccessType().trim().isEmpty()) {
                    keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                    String jbossXml = keycloakAU.getClientJbossXml(service.getOidcClientId());
                    HttpHeaders responseHeaders = new HttpHeaders();
                    responseHeaders.setContentLength(jbossXml.length());
                    responseHeaders.setContentType(MediaType.APPLICATION_XML);
                    return new ResponseEntity<>(jbossXml, responseHeaders, HttpStatus.OK);
                }
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.OIDC_CONF_FILE_NOT_AVAILABLE, request.getServletPath());
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    @Override
    protected Service getCertEntity(Certificate cert) {
        return cert.getService();
    }

    @Override
    protected String getName(CertificateModel certOwner) {
        String name = ((Service)certOwner).getCertDomainName();
        if (name == null || name.trim().isEmpty()) {
            name = ((Service) certOwner).getName();
        } else {
            // Make sure that we only put one domain name in the common name field
            String[] domainNames = name.split(",");
            name = domainNames[0].trim();
        }
        return name;
    }

    protected HashMap<String, String> getAttr(CertificateModel certOwner) {
        HashMap<String, String> attrs = super.getAttr(certOwner);
        // Find special MC attributes to put in the certificate
        Service service = (Service) certOwner;
        String certDomainName = service.getCertDomainName();
        if (certDomainName != null && !certDomainName.trim().isEmpty()) {
            String[] domainNames = certDomainName.split(",");
            for (String domainName : domainNames) {
                attrs.put(PKIConstants.X509_SAN_DNSNAME, domainName.trim());
            }
        }
        return attrs;
    }
}

