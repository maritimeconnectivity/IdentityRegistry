/*
 * Copyright 2020 Maritime Connectivity Platform Consortium.
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
import net.maritimeconnectivity.identityregistry.model.database.entities.MMS;
import net.maritimeconnectivity.identityregistry.services.EntityService;
import net.maritimeconnectivity.identityregistry.utils.AttributesUtil;
import net.maritimeconnectivity.identityregistry.utils.ValidateUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.math.BigInteger;
import java.util.HashMap;

@RestController
public class MMSController extends EntityController<MMS> {

    @Autowired
    public void setEntityService(EntityService<MMS> entityService) {
        this.entityService = entityService;
    }

    /**
     * Creates a new MMS
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */ 
    @RequestMapping(
            value = "/api/org/{orgMrn}/mms",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    @PreAuthorize("hasRole('MMS_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<MMS> createMMS(HttpServletRequest request, @PathVariable String orgMrn, @Valid @RequestBody MMS input, BindingResult bindingResult) throws McBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        return this.createEntity(request, orgMrn, input);
    }

    /**
     * Returns info about the MMS instance identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/mms/{mmsMrn}",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<MMS> getMMS(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String mmsMrn) throws McBasicRestException {
        return this.getEntity(request, orgMrn, mmsMrn);
    }

    /**
     * Updates a mms
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/mms/{mmsMrn}",
            method = RequestMethod.PUT)
    @ResponseBody
    @PreAuthorize("hasRole('MMS_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> updateMMS(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String mmsMrn, @Valid @RequestBody MMS input, BindingResult bindingResult) throws McBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        return this.updateEntity(request, orgMrn, mmsMrn, input);
    }

    /**
     * Deletes a mms
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/mms/{mmsMrn}",
            method = RequestMethod.DELETE)
    @ResponseBody
    @PreAuthorize("hasRole('MMS_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> deleteMMS(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String mmsMrn) throws McBasicRestException {
        return this.deleteEntity(request, orgMrn, mmsMrn);
    }

    /**
     * Returns a list of mmses owned by the organization identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/mmses",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn)")
    public Page<MMS> getOrganizationMMSes(HttpServletRequest request, @PathVariable String orgMrn, Pageable pageable) throws McBasicRestException {
        return this.getOrganizationEntities(request, orgMrn, pageable);
    }

    /**
     * Returns new certificate for the mms identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/mms/{mmsMrn}/certificate/issue-new",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("hasRole('MMS_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<CertificateBundle> newMMSCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String mmsMrn) throws McBasicRestException {
        return this.newEntityCert(request, orgMrn, mmsMrn, "mms");
    }

    /**
     * Takes a certificate signing request and returns a signed certificate with the public key from the csr
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/mms/{mmsMrn}/certificate/issue-new/csr",
            method = RequestMethod.POST,
            consumes = MediaType.TEXT_PLAIN_VALUE,
            produces = {"application/pem-certificate-chain", MediaType.APPLICATION_JSON_UTF8_VALUE}
    )
    @PreAuthorize("hasRole('MMS_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<String> newMMSCertFromCsr(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String mmsMrn, @ApiParam(value = "A PEM encoded PKCS#10 CSR", required = true) @RequestBody String csr) throws McBasicRestException {
        return this.signEntityCert(request, csr, orgMrn, mmsMrn, "mms", null);
    }

    /**
     * Revokes certificate for the mms identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/mms/{mmsMrn}/certificate/{certId}/revoke",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("hasRole('MMS_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> revokeMMSCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String mmsMrn, @ApiParam(value = "The serial number of the certificate given in decimal", required = true) @PathVariable BigInteger certId, @Valid @RequestBody CertificateRevocation input) throws McBasicRestException {
        return this.revokeEntityCert(request, orgMrn, mmsMrn, certId, input);
    }

    @Override
    protected HashMap<String, String> getAttr(CertificateModel certOwner) {
        HashMap<String, String> attrs = super.getAttr(certOwner);
        // Find special MC attributes to put in the certificate
        attrs.putAll(AttributesUtil.getAttributes(certOwner));

        return attrs;
    }

    @Override
    protected MMS getCertEntity(Certificate cert) {
        return cert.getMms();
    }
}

