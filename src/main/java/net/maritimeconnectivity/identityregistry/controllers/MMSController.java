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

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import net.maritimeconnectivity.identityregistry.exception.McpBasicRestException;
import net.maritimeconnectivity.identityregistry.model.data.CertificateRevocation;
import net.maritimeconnectivity.identityregistry.model.database.Certificate;
import net.maritimeconnectivity.identityregistry.model.database.CertificateModel;
import net.maritimeconnectivity.identityregistry.model.database.entities.MMS;
import net.maritimeconnectivity.identityregistry.services.EntityService;
import net.maritimeconnectivity.identityregistry.utils.AttributesUtil;
import net.maritimeconnectivity.identityregistry.utils.ValidateUtil;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
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
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.math.BigInteger;
import java.util.HashMap;

@RestController
public class MMSController extends EntityController<MMS> {

    private static final String TYPE = "mms";

    /**
     * Creates a new MMS
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/{orgMrn}/mms",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Creates a new MMS"
    )
    @ResponseBody
    @PreAuthorize("hasRole('MMS_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'MMS_ADMIN')")
    public ResponseEntity<MMS> createMMS(HttpServletRequest request, @PathVariable String orgMrn, @Valid @RequestBody MMS input, BindingResult bindingResult) throws McpBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        return this.createEntity(request, orgMrn, input);
    }

    /**
     * Returns info about the MMS instance identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/mms/{mmsMrn}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get a specific MMS identity"
    )
    @ResponseBody
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn, null)")
    public ResponseEntity<MMS> getMMS(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String mmsMrn) throws McpBasicRestException {
        return this.getEntity(request, orgMrn, mmsMrn);
    }

    /**
     * Updates a mms
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PutMapping(
            value = "/api/org/{orgMrn}/mms/{mmsMrn}"
    )
    @Operation(
            description = "Update an existing MMS identity"
    )
    @ResponseBody
    @PreAuthorize("hasRole('MMS_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'MMS_ADMIN')")
    public ResponseEntity<?> updateMMS(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String mmsMrn, @Valid @RequestBody MMS input, BindingResult bindingResult) throws McpBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        return this.updateEntity(request, orgMrn, mmsMrn, input);
    }

    /**
     * Deletes a mms
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @DeleteMapping(
            value = "/api/org/{orgMrn}/mms/{mmsMrn}"
    )
    @Operation(
            description = "Delete an MMS identity"
    )
    @ResponseBody
    @PreAuthorize("hasRole('MMS_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'MMS_ADMIN')")
    public ResponseEntity<?> deleteMMS(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String mmsMrn) throws McpBasicRestException {
        return this.deleteEntity(request, orgMrn, mmsMrn);
    }

    /**
     * Returns a list of mmses owned by the organization identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/mmses",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get a page of MMS identities belonging to the given organization"
    )
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn, null)")
    public Page<MMS> getOrganizationMMSes(HttpServletRequest request, @PathVariable String orgMrn, @ParameterObject Pageable pageable) throws McpBasicRestException {
        return this.getOrganizationEntities(request, orgMrn, pageable);
    }

    @GetMapping(
            value = "/api/org/{orgMrn}/mms/{mmsMrn}/certificate/{serialNumber}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get the certificate of the specified MMS with the specified serial number"
    )
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn, null)")
    public ResponseEntity<Certificate> getMMSCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String mmsMrn, @PathVariable BigInteger serialNumber) throws McpBasicRestException {
        return this.getEntityCert(request, orgMrn, mmsMrn, TYPE, null, serialNumber);
    }

    /**
     * Takes a certificate signing request and returns a signed certificate with the public key from the csr
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/{orgMrn}/mms/{mmsMrn}/certificate/issue-new/csr",
            consumes = MediaType.TEXT_PLAIN_VALUE,
            produces = {"application/pem-certificate-chain", MediaType.APPLICATION_JSON_VALUE}
    )
    @Operation(
            description = "Create a new MMS certificate using CSR"
    )
    @PreAuthorize("hasRole('MMS_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'MMS_ADMIN')")
    public ResponseEntity<String> newMMSCertFromCsr(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String mmsMrn, @Parameter(description = "A PEM encoded PKCS#10 CSR", required = true) @RequestBody String csr) throws McpBasicRestException {
        return this.signEntityCert(request, csr, orgMrn, mmsMrn, TYPE, null);
    }

    /**
     * Revokes certificate for the mms identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/{orgMrn}/mms/{mmsMrn}/certificate/{certId}/revoke",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Revoke the MMS certificate with the given serial number"
    )
    @PreAuthorize("hasRole('MMS_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'MMS_ADMIN')")
    public ResponseEntity<?> revokeMMSCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String mmsMrn, @Parameter(description = "The serial number of the certificate given in decimal", required = true) @PathVariable BigInteger certId, @Valid @RequestBody CertificateRevocation input) throws McpBasicRestException {
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

    @Autowired
    public void setEntityService(EntityService<MMS> entityService) {
        this.entityService = entityService;
    }
}

