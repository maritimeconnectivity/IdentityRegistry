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
import org.springframework.security.access.prepost.PreAuthorize;
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
            value = "/api/org/{orgShortName}/service",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<Service> createService(HttpServletRequest request, @PathVariable String orgShortName, @RequestBody Service input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            input.setIdOrganization(org.getId());
            // Setup a keycloak client for the service if needed
            if (input.getOidcAccessType() != null && !input.getOidcAccessType().trim().isEmpty()
                    && input.getOidcRedirectUri() != null && !input.getOidcRedirectUri().trim().isEmpty()) {
                keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                String serviceClientId = (org.getShortName() + "_" + input.getName()).replace(" ", "_");
                input.setOidcClientId(serviceClientId);
                try {
                    String clientSecret = keycloakAU.createClient(serviceClientId, input.getOidcAccessType(), input.getOidcRedirectUri());
                    input.setOidcClientSecret(clientSecret);
                } catch(IOException e) {
                    throw new McBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCIdRegConstants.ERROR_CREATING_ADMIN_KC_USER, request.getServletPath());
                }
            } else {
                input.setOidcAccessType(null);
                input.setOidcClientId(null);
                input.setOidcClientSecret(null);
                input.setOidcRedirectUri(null);
            }
            Service newService = this.entityService.save(input);
            return new ResponseEntity<Service>(newService, HttpStatus.OK);
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
            value = "/api/org/{orgShortName}/service/{serviceId}",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<Service> getService(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long serviceId) throws McBasicRestException {
        return this.getEntity(request, orgShortName, serviceId);
    }

    /**
     * Updates a Service
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/service/{serviceId}",
            method = RequestMethod.PUT)
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<?> updateService(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long serviceId, @RequestBody Service input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            Service service = this.entityService.getById(serviceId);
            if (service == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getId().compareTo(input.getId()) == 0 && service.getIdOrganization().compareTo(org.getId()) == 0) {
                input.selectiveCopyTo(service);
                // Update the keycloak client for the service if needed
                if (service.getOidcAccessType() != null && !service.getOidcAccessType().trim().isEmpty()
                        && service.getOidcRedirectUri() != null && !service.getOidcRedirectUri().trim().isEmpty()) {
                    keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                    String serviceClientId = (org.getShortName() + "_" + service.getName()).replace(" ", "_");
                    keycloakAU.updateClient(serviceClientId, service.getOidcAccessType(), service.getOidcRedirectUri());
                }
                this.entityService.save(service);
                return new ResponseEntity<>(HttpStatus.OK);
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
            value = "/api/org/{orgShortName}/service/{serviceId}",
            method = RequestMethod.DELETE)
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<?> deleteService(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long serviceId) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            Service service = this.entityService.getById(serviceId);
            if (service == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().compareTo(org.getId()) == 0) {
                // Delete the keycloak client for the service if needed
                if (service.getOidcAccessType() != null && !service.getOidcAccessType().trim().isEmpty()
                        && service.getOidcRedirectUri() != null && !service.getOidcRedirectUri().trim().isEmpty()) {
                    keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                    String serviceClientId = (org.getShortName() + "_" + service.getName()).replace(" ", "_");
                    keycloakAU.deleteClient(serviceClientId);
                }
                this.entityService.delete(serviceId);
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
            value = "/api/org/{orgShortName}/services",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<List<Service>> getOrganizationServices(HttpServletRequest request, @PathVariable String orgShortName) throws McBasicRestException {
        return this.getOrganizationEntities(request, orgShortName);
    }

    /**
     * Returns new certificate for the service identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/service/{serviceId}/generatecertificate",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<PemCertificate> newServiceCert(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long serviceId) throws McBasicRestException {
        return this.newEntityCert(request, orgShortName, serviceId, "service");
    }

    /**
     * Revokes certificate for the service identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/service/{serviceId}/certificates/{certId}/revoke",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<?> revokeServiceCert(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long serviceId, @PathVariable Long certId,  @RequestBody CertificateRevocation input) throws McBasicRestException {
        return this.revokeEntityCert(request, orgShortName, serviceId, certId, input);
    }

    /**
     * Returns keycloak.json the service identified by the given ID
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/service/{serviceId}/keycloakjson",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<String> getServiceKeycloakJson(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long serviceId) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            Service service = this.entityService.getById(serviceId);
            if (service == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().compareTo(org.getId()) == 0) {
                // Get the keycloak json for the client the service represents if it exists
                if (service.getOidcAccessType() != null && !service.getOidcAccessType().trim().isEmpty()
                        && service.getOidcRedirectUri() != null && !service.getOidcRedirectUri().trim().isEmpty()) {
                    keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                    String serviceClientId = (org.getShortName() + "_" + service.getName()).replace(" ", "_");
                    String keycloakJson = keycloakAU.getClientKeycloakJson(serviceClientId);
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
            value = "/api/org/{orgShortName}/service/{serviceId}/jbossxml",
            method = RequestMethod.GET,
            produces = "application/xml;charset=UTF-8")
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<String> getServiceJbossXml(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long serviceId) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            Service service = this.entityService.getById(serviceId);
            if (service == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (service.getIdOrganization().compareTo(org.getId()) == 0) {
                // Get the jboss xml for the client the service represents if it exists
                if (service.getOidcAccessType() != null && !service.getOidcAccessType().trim().isEmpty()
                        && service.getOidcRedirectUri() != null && !service.getOidcRedirectUri().trim().isEmpty()) {
                    keycloakAU.init(KeycloakAdminUtil.BROKER_INSTANCE);
                    String serviceClientId = (org.getShortName() + "_" + service.getName()).replace(" ", "_");
                    String jbossXml = keycloakAU.getClientJbossXml(serviceClientId);
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
    protected String getUid(CertificateModel certOwner) {
        return ((Service)certOwner).getServiceOrgId();
    }
}

