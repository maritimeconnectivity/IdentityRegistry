/*
 * Copyright 2017 Danish Maritime Authority.
 * Copyright 2020 Maritime Connectivity Platform Consortium
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

import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.identityregistry.exception.McpBasicRestException;
import net.maritimeconnectivity.identityregistry.model.data.CertificateRevocation;
import net.maritimeconnectivity.identityregistry.model.database.Certificate;
import net.maritimeconnectivity.identityregistry.model.database.CertificateModel;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.model.database.Role;
import net.maritimeconnectivity.identityregistry.model.database.entities.EntityModel;
import net.maritimeconnectivity.identityregistry.services.EntityService;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import net.maritimeconnectivity.identityregistry.services.RoleService;
import net.maritimeconnectivity.identityregistry.services.ServiceService;
import net.maritimeconnectivity.identityregistry.utils.AccessControlUtil;
import net.maritimeconnectivity.identityregistry.utils.CsrUtil;
import net.maritimeconnectivity.identityregistry.utils.ExistsByMrnUtil;
import net.maritimeconnectivity.identityregistry.utils.MCPIdRegConstants;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Slf4j
@RestController
public abstract class EntityController<T extends EntityModel> extends BaseControllerWithCertificate {
    protected EntityService<T> entityService;
    protected OrganizationService organizationService;
    protected RoleService roleService;
    protected AccessControlUtil accessControlUtil;
    protected ExistsByMrnUtil existsByMrnUtil;

    /**
     * Creates a new Entity
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    protected ResponseEntity<T> createEntity(HttpServletRequest request, String orgMrn, T input) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrnNoFilter(orgMrn);
        if (org != null) {
            // Check that the entity being created belongs to the organization
            if (!mrnUtil.entityMrnCorrespondsToOrgMrn(input.getMrn(), org.getMrn())) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            if (existsByMrnUtil.isMrnAlreadyUsed(input.getMrn())) {
                throw new McpBasicRestException(HttpStatus.CONFLICT, MCPIdRegConstants.ENTITY_WITH_MRN_ALREADY_EXISTS, request.getServletPath());
            }
            input.setIdOrganization(org.getId());
            // check that the requesting user has a role that is equal to or higher than the one given to the new entity
            checkRoles(request, input, org);
            if (!mrnUtil.isEntityTypeValid(input)) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, "The entity type in the MRN does not match type of the entity being created.", request.getServletPath());
            }
            T newEntity = null;
            HttpHeaders headers = new HttpHeaders();
            try {
                input.setMrn(input.getMrn().toLowerCase());
                newEntity = this.entityService.save(input);
                String path = request.getRequestURL().append("/").append(URLEncoder.encode(newEntity.getMrn(), StandardCharsets.UTF_8)).toString();
                headers.setLocation(new URI(path));
            } catch (DataIntegrityViolationException e) {
                throw new McpBasicRestException(HttpStatus.CONFLICT, e.getMessage(), request.getServletPath());
            } catch (URISyntaxException e) {
                log.error("Could not create Location header", e);
            }
            return new ResponseEntity<>(newEntity, headers, HttpStatus.CREATED);
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns info about the entity identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    protected ResponseEntity<T> getEntity(HttpServletRequest request, String orgMrn, String entityMrn) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!mrnUtil.entityMrnCorrespondsToOrgMrn(entityMrn, org.getMrn())) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            T entity = this.entityService.getByMrn(entityMrn);
            if (entity == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (entity.getIdOrganization().equals(org.getId())) {
                return new ResponseEntity<>(entity, HttpStatus.OK);
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Updates an entity
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    protected ResponseEntity<?> updateEntity(HttpServletRequest request, String orgMrn, String entityMrn, T input) throws McpBasicRestException {
        if (!entityMrn.equalsIgnoreCase(input.getMrn())) {
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
        }
        Organization org = this.organizationService.getOrganizationByMrnNoFilter(orgMrn);
        if (org != null) {
            // Check that the entity being updated belongs to the organization
            if (!mrnUtil.entityMrnCorrespondsToOrgMrn(entityMrn, org.getMrn())) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            T entity = this.entityService.getByMrn(entityMrn);
            if (entity == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (entity.getIdOrganization().equals(org.getId())) {
                checkRoles(request, input, org);
                input.selectiveCopyTo(entity);
                this.entityService.save(entity);
                return new ResponseEntity<>(HttpStatus.OK);
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Deletes a Device
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    protected ResponseEntity<?> deleteEntity(HttpServletRequest request, String orgMrn, String entityMrn) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrnNoFilter(orgMrn);
        if (org != null) {
            // Check that the entity being deleted belongs to the organization
            if (!mrnUtil.entityMrnCorrespondsToOrgMrn(entityMrn, org.getMrn())) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            T entity = this.entityService.getByMrn(entityMrn);
            if (entity == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (entity.getIdOrganization().equals(org.getId())) {
                this.entityService.delete(entity.getId());
                return new ResponseEntity<>(HttpStatus.OK);
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns a list of entities owned by the organization identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    protected Page<T> getOrganizationEntities(HttpServletRequest request, String orgMrn, Pageable pageable) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            return this.entityService.listPageFromOrg(org.getId(), pageable);
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns the certificate with a specified serial number
     *
     * @param request      the HTTP request
     * @param orgMrn       the organization MRN
     * @param entityMrn    the entity MRN
     * @param type         the entity type
     * @param version      the version if type is service
     * @param serialNumber the serial number of the certificate to be returned
     * @return a PEM encoded certificate chain
     * @throws McpBasicRestException if something goes wrong
     */
    protected ResponseEntity<Certificate> getEntityCert(HttpServletRequest request, String orgMrn, String entityMrn, String type, String version, BigInteger serialNumber) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!mrnUtil.entityMrnCorrespondsToOrgMrn(entityMrn, org.getMrn())) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            EntityModel entity;
            if (type.equals("service") && version != null) {
                entity = ((ServiceService) this.entityService).getServiceByMrnAndVersion(entityMrn, version);
            } else {
                entity = this.entityService.getByMrn(entityMrn);
            }
            if (entity == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (entity.getIdOrganization().equals(org.getId())) {
                Certificate certificate = this.certificateService.getCertificateBySerialNumber(serialNumber);
                if (certificate != null) {
                    return new ResponseEntity<>(certificate, HttpStatus.OK);
                }
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.CERTIFICATE_NOT_FOUND, request.getServletPath());
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Receives a CSR and returns a signed and PEM encoded certificate
     *
     * @return a PEM encoded certificate
     * @throws McpBasicRestException
     */
    protected ResponseEntity<String> signEntityCert(HttpServletRequest request, String csr, String orgMrn, String entityMrn, String type) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrnNoFilter(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!mrnUtil.entityMrnCorrespondsToOrgMrn(entityMrn, org.getMrn())) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }

            EntityModel entity = this.entityService.getByMrn(entityMrn);
            if (entity == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (entity.getIdOrganization().equals(org.getId())) {
                JcaPKCS10CertificationRequest pkcs10CertificationRequest = CsrUtil.getCsrFromPem(request, csr);
                Certificate cert = this.signCertificate(pkcs10CertificationRequest, entity, org, type, request);
                HttpHeaders httpHeaders = new HttpHeaders();
                httpHeaders.setContentType(new MediaType("application", "pem-certificate-chain"));
                try {
                    String path = request.getRequestURL().toString().split("issue-new")[0] + cert.getSerialNumber().toString();
                    httpHeaders.setLocation(new URI(path));
                } catch (URISyntaxException e) {
                    log.error("Could not create Location header", e);
                }
                return new ResponseEntity<>(cert.getCertificate(), httpHeaders, HttpStatus.CREATED);
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Revokes certificate for the entity identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    protected ResponseEntity<?> revokeEntityCert(HttpServletRequest request, String orgMrn, String entityMrn, BigInteger certId, CertificateRevocation input) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrnNoFilter(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!mrnUtil.entityMrnCorrespondsToOrgMrn(entityMrn, org.getMrn())) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            T entity = this.entityService.getByMrn(entityMrn.toLowerCase());
            if (entity == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (entity.getIdOrganization().equals(org.getId())) {
                Certificate cert = this.certificateService.getCertificateBySerialNumber(certId);
                if (cert == null) {
                    throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.CERTIFICATE_NOT_FOUND, request.getServletPath());
                }
                T certEntity = getCertEntity(cert);
                if (certEntity != null && certEntity.getId().equals(entity.getId())) {
                    this.revokeCertificate(cert.getSerialNumber(), input, request);
                    return new ResponseEntity<>(HttpStatus.OK);
                }
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    protected T getCertEntity(Certificate cert) {
        throw new UnsupportedOperationException("EntityController implementation is missing getCertEntity method");
    }

    protected String getUid(CertificateModel certOwner) {
        return ((EntityModel) certOwner).getMrn();
    }

    // Checks that the requesting user has a role that is equal to or higher than the ones being given to the input

    protected void checkRoles(HttpServletRequest request, T input, Organization org) throws McpBasicRestException {
        if (input.getPermissions() != null) {
            String[] permissions = input.getPermissions().split(",");
            for (String permission : permissions) {
                List<Role> roleList = this.roleService.getRolesByIdOrganizationAndPermission(org.getId(), permission);
                for (Role role : roleList) {
                    if (!accessControlUtil.hasRole(role.getRoleName())) {
                        throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
                    }
                }
            }
        }
    }

    @Autowired
    public void setOrganizationService(OrganizationService organizationService) {
        this.organizationService = organizationService;
    }

    @Autowired
    public void setRoleService(RoleService roleService) {
        this.roleService = roleService;
    }

    @Autowired
    public void setAccessControlUtil(AccessControlUtil accessControlUtil) {
        this.accessControlUtil = accessControlUtil;
    }

    @Autowired
    public void setExistsByMrnUtil(ExistsByMrnUtil existsByMrnUtil) {
        this.existsByMrnUtil = existsByMrnUtil;
    }
}
