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

import net.maritimeconnectivity.identityregistry.exception.McBasicRestException;
import net.maritimeconnectivity.identityregistry.model.data.CertificateBundle;
import net.maritimeconnectivity.identityregistry.model.data.CertificateRevocation;
import net.maritimeconnectivity.identityregistry.model.database.Certificate;
import net.maritimeconnectivity.identityregistry.model.database.CertificateModel;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.model.database.Role;
import net.maritimeconnectivity.identityregistry.model.database.entities.EntityModel;
import net.maritimeconnectivity.identityregistry.services.CertificateService;
import net.maritimeconnectivity.identityregistry.services.EntityService;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import net.maritimeconnectivity.identityregistry.services.RoleService;
import net.maritimeconnectivity.identityregistry.services.ServiceService;
import net.maritimeconnectivity.identityregistry.utils.AccessControlUtil;
import net.maritimeconnectivity.identityregistry.utils.CertificateUtil;
import net.maritimeconnectivity.identityregistry.utils.CsrUtil;
import net.maritimeconnectivity.identityregistry.utils.MCIdRegConstants;
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

import javax.servlet.http.HttpServletRequest;
import java.math.BigInteger;
import java.util.List;

@RestController
public abstract class EntityController<T extends EntityModel> extends BaseControllerWithCertificate {
    protected EntityService<T> entityService;
    protected OrganizationService organizationService;
    protected CertificateService certificateService;
    protected RoleService roleService;
    protected CertificateUtil certUtil;
    protected AccessControlUtil accessControlUtil;

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
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
    public void setCertUtil(CertificateUtil certUtil) {
        this.certUtil = certUtil;
    }

    @Autowired
    public void setAccessControlUtil(AccessControlUtil accessControlUtil) {
        this.accessControlUtil = accessControlUtil;
    }

    /**
     * Creates a new Entity
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    protected ResponseEntity<T> createEntity(HttpServletRequest request, String orgMrn, T input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being created belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(input.getMrn()))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            input.setIdOrganization(org.getId());
            // check that the requesting user has a role that is equal to or higher than the one given to the new entity
            checkRoles(request, input, org);
            try {
                input.setMrn(input.getMrn().toLowerCase());
                T newEntity = this.entityService.save(input);
                return new ResponseEntity<>(newEntity, HttpStatus.OK);
            } catch (DataIntegrityViolationException e) {
                throw new McBasicRestException(HttpStatus.CONFLICT, e.getMessage(), request.getServletPath());
            }
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns info about the entity identified by the given ID
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    protected ResponseEntity<T> getEntity(HttpServletRequest request, String orgMrn, String entityMrn) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(entityMrn))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            T entity = this.entityService.getByMrn(entityMrn);
            if (entity == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (entity.getIdOrganization().compareTo(org.getId()) == 0) {
                return new ResponseEntity<>(entity, HttpStatus.OK);
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Updates an entity
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    protected ResponseEntity<?> updateEntity(HttpServletRequest request, String orgMrn, String entityMrn, T input) throws McBasicRestException {
        if (!entityMrn.equalsIgnoreCase(input.getMrn())) {
            throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
        }
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being updated belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(entityMrn))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            T entity = this.entityService.getByMrn(entityMrn);
            if (entity == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (entity.getIdOrganization().compareTo(org.getId()) == 0) {
                checkRoles(request, input, org);
                input.selectiveCopyTo(entity);
                this.entityService.save(entity);
                return new ResponseEntity<>(HttpStatus.OK);
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Deletes a Device
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    protected ResponseEntity<?> deleteEntity(HttpServletRequest request, String orgMrn, String entityMrn) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being deleted belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(entityMrn))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            T entity = this.entityService.getByMrn(entityMrn);
            if (entity == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (entity.getIdOrganization().compareTo(org.getId()) == 0) {
                this.entityService.delete(entity.getId());
                return new ResponseEntity<>(HttpStatus.OK);
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns a list of entities owned by the organization identified by the given ID
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    protected Page<T> getOrganizationEntities(HttpServletRequest request, String orgMrn, Pageable pageable) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            return this.entityService.listPageFromOrg(org.getId(), pageable);
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Receives a CSR and returns a signed and PEM encoded certificate
     * @return a PEM encoded certificate
     * @throws McBasicRestException
     */
    protected ResponseEntity<String> signEntityCert(HttpServletRequest request, String csr, String orgMrn, String entityMrn, String type, String version) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(entityMrn))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            EntityModel entity;
            if (type.equals("service")) {
                entity = ((ServiceService) this.entityService).getServiceByMrnAndVersion(entityMrn, version);
            } else {
                entity = this.entityService.getByMrn(entityMrn);
            }
            if (entity == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (entity.getIdOrganization().compareTo(org.getId()) == 0) {
                JcaPKCS10CertificationRequest pkcs10CertificationRequest = CsrUtil.getCsrFromPem(request, csr);
                String cert = this.signCertificate(pkcs10CertificationRequest, entity, org, type, request);
                HttpHeaders httpHeaders = new HttpHeaders();
                httpHeaders.setContentType(new MediaType("application", "pem-certificate-chain"));
                return new ResponseEntity<>(cert, httpHeaders, HttpStatus.OK);
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }


    /**
     * Returns new certificate for the entity identified by the given ID
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    protected ResponseEntity<CertificateBundle> newEntityCert(HttpServletRequest request, String orgMrn, String entityMrn, String type) throws McBasicRestException {
        String oidcOrX509 = request.getServletPath().split("/")[1];
        String path = String.format("/%s/api/org/%s/%s/%s/certificate/issue-new/csr", oidcOrX509, orgMrn, type, entityMrn);
        throw new McBasicRestException(HttpStatus.GONE, String.format("Certificate issuing with server generated key pairs is no longer supported. " +
                "Please POST a certificate signing request to %s instead.", path), request.getContextPath());
    }

    /**
     * Revokes certificate for the entity identified by the given ID
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    protected ResponseEntity<?> revokeEntityCert(HttpServletRequest request, String orgMrn, String entityMrn, BigInteger certId, CertificateRevocation input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(entityMrn))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            T entity = this.entityService.getByMrn(entityMrn.toLowerCase());
            if (entity == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (entity.getIdOrganization().compareTo(org.getId()) == 0) {
                Certificate cert = this.certificateService.getCertificateBySerialNumber(certId);
                T certEntity = getCertEntity(cert);
                if (certEntity != null && certEntity.getId().compareTo(entity.getId()) == 0) {
                    this.revokeCertificate(cert.getSerialNumber(), input, request);
                    return new ResponseEntity<>(HttpStatus.OK);
                }
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    protected T getCertEntity(Certificate cert) {
        throw new UnsupportedOperationException("EntityController implementation is missing getCertEntity method");
    }

    protected String getUid(CertificateModel certOwner) {
        return ((EntityModel)certOwner).getMrn();
    }

    // Checks that the requesting user has a role that is equal to or higher than the ones being given to the input
    protected void checkRoles(HttpServletRequest request, T input, Organization org) throws McBasicRestException {
        if (input.getPermissions() != null) {
            String[] permissions = input.getPermissions().split(",");
            for (String permission : permissions) {
                List<Role> roleList = this.roleService.getRolesByIdOrganizationAndPermission(org.getId(), permission);
                for (Role role : roleList) {
                    if (!accessControlUtil.hasRole(role.getRoleName())) {
                        throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
                    }
                }
            }
        }
    }

}
