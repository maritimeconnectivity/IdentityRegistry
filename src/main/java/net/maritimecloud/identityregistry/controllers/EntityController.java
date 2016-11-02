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
import net.maritimecloud.identityregistry.model.database.entities.EntityModel;
import net.maritimecloud.identityregistry.services.EntityService;
import net.maritimecloud.identityregistry.utils.MrnUtil;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.web.bind.annotation.RestController;

import net.maritimecloud.identityregistry.exception.McBasicRestException;
import net.maritimecloud.identityregistry.model.database.Certificate;
import net.maritimecloud.identityregistry.model.data.CertificateRevocation;
import net.maritimecloud.identityregistry.model.database.Organization;
import net.maritimecloud.identityregistry.model.data.PemCertificate;
import net.maritimecloud.identityregistry.services.CertificateService;
import net.maritimecloud.identityregistry.services.OrganizationService;
import net.maritimecloud.identityregistry.utils.CertificateUtil;
import net.maritimecloud.identityregistry.utils.MCIdRegConstants;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@RestController
public abstract class EntityController<T extends EntityModel> extends BaseControllerWithCertificate {
    protected EntityService<T> entityService;
    protected OrganizationService organizationService;
    protected CertificateService certificateService;

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setOrganizationService(OrganizationService organizationService) {
        this.organizationService = organizationService;
    }

    @Autowired
    protected CertificateUtil certUtil;

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
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equals(MrnUtil.getOrgShortNameFromEntityMrn(input.getMrn()))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            input.setIdOrganization(org.getId());
            try {
                T newEntity = this.entityService.save(input);
                return new ResponseEntity<T>(newEntity, HttpStatus.OK);
            } catch (DataIntegrityViolationException e) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, e.getRootCause().getMessage(), request.getServletPath());
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
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equals(MrnUtil.getOrgShortNameFromEntityMrn(entityMrn))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            T entity = this.entityService.getByMrn(entityMrn);
            if (entity == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (entity.getIdOrganization().compareTo(org.getId()) == 0) {
                return new ResponseEntity<T>(entity, HttpStatus.OK);
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
        if (!entityMrn.equals(input.getMrn())) {
            throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
        }
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being updated belongs to the organization
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equals(MrnUtil.getOrgShortNameFromEntityMrn(entityMrn))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            T entity = this.entityService.getByMrn(entityMrn);
            if (entity == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (entity.getIdOrganization().compareTo(org.getId()) == 0) {
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
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equals(MrnUtil.getOrgShortNameFromEntityMrn(entityMrn))) {
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
    protected ResponseEntity<List<T>> getOrganizationEntities(HttpServletRequest request, String orgMrn) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            List<T> entities = this.entityService.listFromOrg(org.getId());
            return new ResponseEntity<List<T>>(entities, HttpStatus.OK);
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
    protected ResponseEntity<PemCertificate> newEntityCert(HttpServletRequest request, String orgMrn, String entityMrn, String type) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equals(MrnUtil.getOrgShortNameFromEntityMrn(entityMrn))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            T entity = this.entityService.getByMrn(entityMrn);
            if (entity == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (entity.getIdOrganization().compareTo(org.getId()) == 0) {
                PemCertificate ret = this.issueCertificate(entity, org, type, request);
                return new ResponseEntity<PemCertificate>(ret, HttpStatus.OK);
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Revokes certificate for the entity identified by the given ID
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    protected ResponseEntity<?> revokeEntityCert(HttpServletRequest request, String orgMrn, String entityMrn, Long certId, CertificateRevocation input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            // Check that the entity being queried belongs to the organization
            if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equals(MrnUtil.getOrgShortNameFromEntityMrn(entityMrn))) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            T entity = this.entityService.getByMrn(entityMrn);
            if (entity == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ENTITY_NOT_FOUND, request.getServletPath());
            }
            if (entity.getIdOrganization().compareTo(org.getId()) == 0) {
                Certificate cert = this.certificateService.getCertificateById(certId);
                T certEntity = getCertEntity(cert);
                if (certEntity != null && certEntity.getId().compareTo(entity.getId()) == 0) {
                    this.revokeCertificate(cert.getId(), input, request);
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

}

