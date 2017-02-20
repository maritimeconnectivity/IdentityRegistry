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

import net.maritimecloud.identityregistry.model.database.CertificateModel;
import net.maritimecloud.identityregistry.utils.MrnUtil;
import net.maritimecloud.identityregistry.utils.ValidateUtil;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.RestController;

import net.maritimecloud.identityregistry.exception.McBasicRestException;
import net.maritimecloud.identityregistry.model.database.Certificate;
import net.maritimecloud.identityregistry.model.data.CertificateRevocation;
import net.maritimecloud.identityregistry.model.database.Organization;
import net.maritimecloud.identityregistry.model.data.PemCertificate;
import net.maritimecloud.identityregistry.model.database.entities.Service;
import net.maritimecloud.identityregistry.services.EntityService;
import net.maritimecloud.identityregistry.utils.KeycloakAdminUtil;
import net.maritimecloud.identityregistry.utils.MCIdRegConstants;

import java.io.IOException;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
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
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equals(MrnUtil.getOrgShortNameFromEntityMrn(input.getMrn()))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            input.setIdOrganization(org.getId());
            // Setup a keycloak client for the service if needed
            if (input.getOidcAccessType() != null && !input.getOidcAccessType().trim().isEmpty()) {
                // Check if the redirect uri is set if access type is "bearer-only"
                if (!"bearer-only".equals(input.getOidcAccessType()) && (input.getOidcRedirectUri() == null || input.getOidcRedirectUri().trim().isEmpty())) {
                    throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.OIDC_MISSING_REDIRECT_URL, request.getServletPath());
                }
                keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                input.setOidcClientId(input.getMrn());
                try {
                    String clientSecret = keycloakAU.createClient(input.getMrn(), input.getOidcAccessType(), input.getOidcRedirectUri());
                    if ("confidential".equals(input.getOidcAccessType())) {
                        input.setOidcClientSecret(clientSecret);
                    } else {
                        input.setOidcClientSecret(null);
                    }
                } catch(IOException e) {
                    throw new McBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCIdRegConstants.ERROR_CREATING_KC_CLIENT, request.getServletPath());
                }
            } else {
                input.setOidcAccessType(null);
                input.setOidcClientId(null);
                input.setOidcClientSecret(null);
                input.setOidcRedirectUri(null);
            }
            try {
                Service newService = this.entityService.save(input);
                return new ResponseEntity<Service>(newService, HttpStatus.OK);
            } catch (DataIntegrityViolationException e) {
                // If save to DB failed, remove the client from keycloak if it was created.
                if (input.getOidcAccessType() != null && !input.getOidcAccessType().trim().isEmpty()) {
                    keycloakAU.deleteClient(input.getMrn());
                }
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, e.getRootCause().getMessage(), request.getServletPath());
            }
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns info about the service identified by the given ID
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
    public ResponseEntity<Service> getService(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn) throws McBasicRestException {
        return this.getEntity(request, orgMrn, serviceMrn);
    }

    /**
     * Updates a Service
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}",
            method = RequestMethod.PUT)
    @ResponseBody
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> updateService(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @Valid @RequestBody Service input, BindingResult bindingResult) throws McBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        if (!serviceMrn.equals(input.getMrn())) {
            throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
        }
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being updated belongs to the organization
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equals(MrnUtil.getOrgShortNameFromEntityMrn(input.getMrn()))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = this.entityService.getByMrn(serviceMrn);
            if (service == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().compareTo(org.getId()) == 0) {
                // Update the keycloak client for the service if needed
                if (input.getOidcAccessType() != null && !input.getOidcAccessType().trim().isEmpty()) {
                    // Check if the redirect uri is set if access type is "bearer-only"
                    if (!"bearer-only".equals(input.getOidcAccessType()) && (input.getOidcRedirectUri() == null || input.getOidcRedirectUri().trim().isEmpty())) {
                        throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.OIDC_MISSING_REDIRECT_URL, request.getServletPath());
                    }
                    keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                    String clientSecret;
                    try {
                        if (service.getOidcClientId() != null && !service.getOidcClientId().isEmpty()) {
                            clientSecret = keycloakAU.updateClient(service.getMrn(), service.getOidcAccessType(), service.getOidcRedirectUri());
                        } else {
                            service.setOidcClientId(service.getMrn());
                            clientSecret = keycloakAU.createClient(service.getMrn(), service.getOidcAccessType(), service.getOidcRedirectUri());
                        }
                    } catch (IOException e){
                        throw new McBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCIdRegConstants.ERROR_UPDATING_KC_USER, request.getServletPath());
                    }
                    if ("confidential".equals(service.getOidcAccessType())) {
                        service.setOidcClientSecret(clientSecret);
                    } else {
                        service.setOidcClientSecret(null);
                    }
                }
                input.selectiveCopyTo(service);
                try {
                    this.entityService.save(service);
                    return new ResponseEntity<>(HttpStatus.OK);
                } catch (DataIntegrityViolationException e) {
                    throw new McBasicRestException(HttpStatus.BAD_REQUEST, e.getRootCause().getMessage(), request.getServletPath());
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
            value = "/api/org/{orgMrn}/service/{serviceMrn}",
            method = RequestMethod.DELETE)
    @ResponseBody
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> deleteService(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being deleted belongs to the organization
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equals(MrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = this.entityService.getByMrn(serviceMrn);
            if (service == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().compareTo(org.getId()) == 0) {
                // Delete the keycloak client for the service if needed
                if (service.getOidcAccessType() != null && !service.getOidcAccessType().trim().isEmpty()
                        && service.getOidcRedirectUri() != null && !service.getOidcRedirectUri().trim().isEmpty()) {
                    keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                    keycloakAU.deleteClient(service.getMrn());
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
    public ResponseEntity<List<Service>> getOrganizationServices(HttpServletRequest request, @PathVariable String orgMrn) throws McBasicRestException {
        return this.getOrganizationEntities(request, orgMrn);
    }

    /**
     * Returns new certificate for the service identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/certificate/issue-new",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<PemCertificate> newServiceCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn) throws McBasicRestException {
        return this.newEntityCert(request, orgMrn, serviceMrn, "service");
    }

    /**
     * Revokes certificate for the service identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/certificate/{certId}/revoke",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> revokeServiceCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn, @PathVariable Long certId, @Valid @RequestBody CertificateRevocation input) throws McBasicRestException {
        return this.revokeEntityCert(request, orgMrn, serviceMrn, certId, input);
    }

    /**
     * Returns keycloak.json the service identified by the given ID
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/service/{serviceMrn}/keycloakjson",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<String> getServiceKeycloakJson(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equals(MrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = this.entityService.getByMrn(serviceMrn);
            if (service == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().compareTo(org.getId()) == 0) {
                // Get the keycloak json for the client the service represents if it exists
                if (service.getOidcAccessType() != null && !service.getOidcAccessType().trim().isEmpty()
                        && service.getOidcRedirectUri() != null && !service.getOidcRedirectUri().trim().isEmpty()) {
                    keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                    String keycloakJson = keycloakAU.getClientKeycloakJson(service.getMrn());
                    return new ResponseEntity<String>(keycloakJson, HttpStatus.OK);
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
            value = "/api/org/{orgMrn}/service/{serviceMrn}/jbossxml",
            method = RequestMethod.GET,
            produces = "application/xml;charset=UTF-8")
    @ResponseBody
    @PreAuthorize("hasRole('SERVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<String> getServiceJbossXml(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String serviceMrn) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equals(MrnUtil.getOrgShortNameFromEntityMrn(serviceMrn))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            Service service = this.entityService.getByMrn(serviceMrn);
            if (service == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().compareTo(org.getId()) == 0) {
                // Get the jboss xml for the client the service represents if it exists
                if (service.getOidcAccessType() != null && !service.getOidcAccessType().trim().isEmpty()
                        && service.getOidcRedirectUri() != null && !service.getOidcRedirectUri().trim().isEmpty()) {
                    keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                    String jbossXml = keycloakAU.getClientJbossXml(service.getMrn());
                    return new ResponseEntity<String>(jbossXml, HttpStatus.OK);
                }
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
        }
        return name;
    }

}

