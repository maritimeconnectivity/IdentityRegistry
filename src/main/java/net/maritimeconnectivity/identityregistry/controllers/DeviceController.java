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
import net.maritimeconnectivity.identityregistry.model.data.CertificateBundle;
import net.maritimeconnectivity.identityregistry.model.data.CertificateRevocation;
import net.maritimeconnectivity.identityregistry.model.database.Certificate;
import net.maritimeconnectivity.identityregistry.model.database.entities.Device;
import net.maritimeconnectivity.identityregistry.services.EntityService;
import net.maritimeconnectivity.identityregistry.utils.ValidateUtil;
import org.springdoc.api.annotations.ParameterObject;
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

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.math.BigInteger;

@RestController
public class DeviceController extends EntityController<Device> {

    private static final String TYPE = "device";

    /**
     * Creates a new Device
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/{orgMrn}/device",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @ResponseBody
    @PreAuthorize("hasRole('DEVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'DEVICE_ADMIN')")
    public ResponseEntity<Device> createDevice(HttpServletRequest request, @PathVariable String orgMrn, @Valid @RequestBody Device input, BindingResult bindingResult) throws McpBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        return this.createEntity(request, orgMrn, input);
    }

    /**
     * Returns info about the device identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/device/{deviceMrn}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @ResponseBody
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn, null)")
    public ResponseEntity<Device> getDevice(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String deviceMrn) throws McpBasicRestException {
        return this.getEntity(request, orgMrn, deviceMrn);
    }

    /**
     * Updates a Device
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PutMapping(
            value = "/api/org/{orgMrn}/device/{deviceMrn}"
    )
    @ResponseBody
    @PreAuthorize("hasRole('DEVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'DEVICE_ADMIN')")
    public ResponseEntity<?> updateDevice(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String deviceMrn, @Valid @RequestBody Device input, BindingResult bindingResult) throws McpBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        return this.updateEntity(request, orgMrn, deviceMrn, input);
    }

    /**
     * Deletes a Device
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @DeleteMapping(
            value = "/api/org/{orgMrn}/device/{deviceMrn}"
    )
    @ResponseBody
    @PreAuthorize("hasRole('DEVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'DEVICE_ADMIN')")
    public ResponseEntity<?> deleteDevice(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String deviceMrn) throws McpBasicRestException {
        return this.deleteEntity(request, orgMrn, deviceMrn);
    }

    /**
     * Returns a list of devices owned by the organization identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/devices",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn, null)")
    public Page<Device> getOrganizationDevices(HttpServletRequest request, @PathVariable String orgMrn, @ParameterObject Pageable pageable) throws McpBasicRestException {
        return this.getOrganizationEntities(request, orgMrn, pageable);
    }

    @GetMapping(
            value = "/api/org/{orgMrn}/device/{deviceMrn}/certificate/{serialNumber}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn, null)")
    public ResponseEntity<Certificate> getDeviceCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String deviceMrn, @PathVariable BigInteger serialNumber) throws McpBasicRestException {
        return this.getEntityCert(request, orgMrn, deviceMrn, TYPE, null, serialNumber);
    }

    /**
     * Returns new certificate for the device identified by the given ID
     *
     * @deprecated It is generally not considered secure letting the server generate the private key. Will be removed in the future
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @Operation(
            description = "DEPRECATED: Issues a bundle containing a certificate, the key pair of the certificate " +
                    "and keystores in JKS and PKCS#12 formats. As server generated key pairs are not considered secure " +
                    "this endpoint should not be used, and anybody who does should migrate to the endpoint for issuing " +
                    "certificates using certificate signing requests as soon as possible. This endpoint will be removed " +
                    "completely in the future and providers may choose to already disable it now which will result in an error if called."
    )
    @GetMapping(
            value = "/api/org/{orgMrn}/device/{deviceMrn}/certificate/issue-new",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @PreAuthorize("hasRole('DEVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'DEVICE_ADMIN')")
    @Deprecated
    public ResponseEntity<CertificateBundle> newDeviceCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String deviceMrn) throws McpBasicRestException {
        return this.newEntityCert(request, orgMrn, deviceMrn, TYPE);
    }

    /**
     * Takes a certificate signing request and returns a signed certificate with the public key from the csr
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/{orgMrn}/device/{deviceMrn}/certificate/issue-new/csr",
            consumes = MediaType.TEXT_PLAIN_VALUE,
            produces = {"application/pem-certificate-chain", MediaType.APPLICATION_JSON_VALUE}
    )
    @PreAuthorize("hasRole('DEVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'DEVICE_ADMIN')")
    public ResponseEntity<String> newDeviceCertFromCsr(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String deviceMrn, @Parameter(description = "A PEM encoded PKCS#10 CSR", required = true) @RequestBody String csr) throws McpBasicRestException {
        return this.signEntityCert(request, csr, orgMrn, deviceMrn, TYPE, null);
    }

    /**
     * Revokes certificate for the device identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/{orgMrn}/device/{deviceMrn}/certificate/{certId}/revoke",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @PreAuthorize("hasRole('DEVICE_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'DEVICE_ADMIN')")
    public ResponseEntity<?> revokeDeviceCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String deviceMrn, @Parameter(description = "The serial number of the certificate given in decimal", required = true) @PathVariable BigInteger certId, @Valid @RequestBody CertificateRevocation input) throws McpBasicRestException {
        return this.revokeEntityCert(request, orgMrn, deviceMrn, certId, input);
    }

    @Override
    protected Device getCertEntity(Certificate cert) {
        return cert.getDevice();
    }

    @Autowired
    public void setEntityService(EntityService<Device> entityService) {
        this.entityService = entityService;
    }
}

