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
import net.maritimeconnectivity.identityregistry.exception.McpBasicRestException;
import net.maritimeconnectivity.identityregistry.model.data.CertificateRevocation;
import net.maritimeconnectivity.identityregistry.model.database.Certificate;
import net.maritimeconnectivity.identityregistry.model.database.CertificateModel;
import net.maritimeconnectivity.identityregistry.model.database.entities.Service;
import net.maritimeconnectivity.identityregistry.model.database.entities.Vessel;
import net.maritimeconnectivity.identityregistry.services.EntityService;
import net.maritimeconnectivity.identityregistry.utils.AttributesUtil;
import net.maritimeconnectivity.identityregistry.utils.MCPIdRegConstants;
import net.maritimeconnectivity.identityregistry.utils.ValidateUtil;
import org.springdoc.api.annotations.ParameterObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
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
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Set;

@RestController
public class VesselController extends EntityController<Vessel> {

    private static final String TYPE = "vessel";

    /**
     * Creates a new Vessel
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/{orgMrn}/vessel",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Create a new vessel identity"
    )
    @ResponseBody
    @PreAuthorize("hasRole('VESSEL_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'VESSEL_ADMIN')")
    public ResponseEntity<Vessel> createVessel(HttpServletRequest request, @PathVariable String orgMrn, @Valid @RequestBody Vessel input, BindingResult bindingResult) throws McpBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        return this.createEntity(request, orgMrn, input);
    }

    /**
     * Returns info about the vessel identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/vessel/{vesselMrn}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get a specific vessel identity"
    )
    @ResponseBody
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn, null)")
    public ResponseEntity<Vessel> getVessel(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String vesselMrn) throws McpBasicRestException {
        return this.getEntity(request, orgMrn, vesselMrn);
    }

    /**
     * Updates a Vessel
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PutMapping(
            value = "/api/org/{orgMrn}/vessel/{vesselMrn}"
    )
    @Operation(
            description = "Update a specific vessel identity"
    )
    @ResponseBody
    @PreAuthorize("hasRole('VESSEL_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'VESSEL_ADMIN')")
    public ResponseEntity<?> updateVessel(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String vesselMrn, @Valid @RequestBody Vessel input, BindingResult bindingResult) throws McpBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        return this.updateEntity(request, orgMrn, vesselMrn, input);
    }

    /**
     * Returns the set of services that has a relation with a specific vessel
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/vessel/{vesselMrn}/services",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get the set of service identities that are linked to the specified vessel identity"
    )
    @ResponseBody
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn, null)")
    public ResponseEntity<Set<Service>> getVesselServices(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String vesselMrn) throws McpBasicRestException {
        if (!mrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(mrnUtil.getOrgShortNameFromEntityMrn(vesselMrn))) {
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        }
        Vessel vessel = this.entityService.getByMrn(vesselMrn);
        Set<Service> services = vessel.getServices();
        return new ResponseEntity<>(services, HttpStatus.OK);
    }

    /**
     * Deletes a Vessel
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @DeleteMapping(
            value = "/api/org/{orgMrn}/vessel/{vesselMrn}"
    )
    @Operation(
            description = "Delete a specific vessel identity"
    )
    @ResponseBody
    @PreAuthorize("hasRole('VESSEL_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'VESSEL_ADMIN')")
    public ResponseEntity<?> deleteVessel(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String vesselMrn) throws McpBasicRestException {
        return this.deleteEntity(request, orgMrn, vesselMrn);
    }

    /**
     * Returns a list of vessels owned by the organization identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/vessels",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get a page of vessel identities of the specified organization"
    )
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn, null)")
    public Page<Vessel> getOrganizationVessels(HttpServletRequest request, @PathVariable String orgMrn, @ParameterObject Pageable pageable) throws McpBasicRestException {
        return this.getOrganizationEntities(request, orgMrn, pageable);
    }

    @GetMapping(
            value = "/api/org/{orgMrn}/vessel/{vesselMrn}/certificate/{serialNumber}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get the vessel identity certificate with the given serial number"
    )
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn, null)")
    public ResponseEntity<Certificate> getVesselCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String vesselMrn, @PathVariable BigInteger serialNumber) throws McpBasicRestException {
        return this.getEntityCert(request, orgMrn, vesselMrn, TYPE, null, serialNumber);
    }

    /**
     * Takes a certificate signing request and returns a signed certificate with the public key from the csr
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/{orgMrn}/vessel/{vesselMrn}/certificate/issue-new/csr",
            consumes = MediaType.TEXT_PLAIN_VALUE,
            produces = {"application/pem-certificate-chain", MediaType.APPLICATION_JSON_VALUE}
    )
    @Operation(
            description = "Create a new vessel identity certificate using CSR"
    )
    @PreAuthorize("hasRole('VESSEL_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'VESSEL_ADMIN')")
    public ResponseEntity<String> newVesselCertFromCsr(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String vesselMrn, @Parameter(description = "A PEM encoded PKCS#10 CSR", required = true) @RequestBody String csr) throws McpBasicRestException {
        return this.signEntityCert(request, csr, orgMrn, vesselMrn, TYPE, null);
    }

    /**
     * Revokes certificate for the vessel identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/{orgMrn}/vessel/{vesselMrn}/certificate/{certId}/revoke",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Revoke the vessel identity certificate with the given serial number"
    )
    @PreAuthorize("hasRole('VESSEL_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'VESSEL_ADMIN')")
    public ResponseEntity<?> revokeVesselCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String vesselMrn, @Parameter(description = "The serial number of the certificate given in decimal", required = true) @PathVariable BigInteger certId, @Valid @RequestBody CertificateRevocation input) throws McpBasicRestException {
        return this.revokeEntityCert(request, orgMrn, vesselMrn, certId, input);
    }

    @Override
    protected HashMap<String, String> getAttr(CertificateModel certOwner) {
        HashMap<String, String> attrs = super.getAttr(certOwner);
        // Find special MC attributes to put in the certificate
        attrs.putAll(AttributesUtil.getAttributes(certOwner));

        return attrs;
    }

    @Override
    protected Vessel getCertEntity(Certificate cert) {
        return cert.getVessel();
    }

    @Autowired
    public void setVesselService(EntityService<Vessel> vesselService) {
        this.entityService = vesselService;
    }
}
