/*
 * Copyright 2024 Maritime Connectivity Platform Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.maritimeconnectivity.identityregistry.controllers.secom;

import io.swagger.v3.oas.annotations.Operation;
import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.identityregistry.model.database.Certificate;
import net.maritimeconnectivity.identityregistry.model.database.CertificateModel;
import net.maritimeconnectivity.identityregistry.model.database.entities.Service;
import net.maritimeconnectivity.identityregistry.model.database.entities.User;
import net.maritimeconnectivity.identityregistry.services.CertificateService;
import net.maritimeconnectivity.identityregistry.services.DeviceServiceImpl;
import net.maritimeconnectivity.identityregistry.services.EntityService;
import net.maritimeconnectivity.identityregistry.services.MMSService;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import net.maritimeconnectivity.identityregistry.services.ServiceService;
import net.maritimeconnectivity.identityregistry.services.VesselServiceImpl;
import net.maritimeconnectivity.identityregistry.utils.MrnUtil;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigInteger;
import java.util.List;
import java.util.regex.Pattern;

@RestController
@RequestMapping(value = "/secom/v1")
@Slf4j
public class SecomController {

    private MrnUtil mrnUtil;
    private CertificateService certificateService;
    private DeviceServiceImpl deviceService;
    private MMSService mmsService;
    private OrganizationService organizationService;
    private ServiceService serviceService;
    private EntityService<User> userService;
    private VesselServiceImpl vesselService;
    private final Pattern serialNumberPattern = Pattern.compile("^\\d+$");

    @GetMapping(
            value = "/publicKey/{parameter}",
            produces = "application/x-pem-file"
    )
    @Operation(
            description = "Returns 0 or more certificates (public keys). Based on the REST definition of the GetPublicKey " +
                    "interface definition from IEC 63173-2:2022 (SECOM). The input parameter can either be the " +
                    "serial number or base64 encoded SHA-256 thumbprint of the wanted certificate. It is also possible " +
                    "to provide the MRN of an MCP entity to get the list of all active certificate of that entity."
    )
    public ResponseEntity<String> getPublicKey(@PathVariable String parameter) {
        String ret = null;
        // check if the parameter is a certificate thumbprint
        if (Base64.isBase64(parameter)) {
            Certificate certificate = certificateService.getCertificateByThumbprint(parameter);
            if (certificate != null) {
                ret = certificate.getCertificate();
            }
            // else, check if it is a serial number
        } else if (serialNumberPattern.matcher(parameter).matches()) {
            BigInteger serialNumber = new BigInteger(parameter);
            Certificate certificate = certificateService.getCertificateBySerialNumber(serialNumber);
            if (certificate != null) {
                ret = certificate.getCertificate();
            }
            // else, check if it is an MCP MRN
        } else if (mrnUtil.mcpMrnPattern.matcher(parameter).matches()) {
            ret = getCertsForMrn(parameter);
        }

        if (ret != null && !ret.isEmpty()) {
            return ResponseEntity.ok(ret);
        }
        return ResponseEntity.notFound().build();
    }

    private String getCertsForMrn(String mrn) {
        String type = mrnUtil.getEntityType(mrn);
        String ret = null;
        CertificateModel entity = switch (type) {
            case "device" -> deviceService.getByMrn(mrn);
            case "mms" -> mmsService.getByMrn(mrn);
            case "organization" -> organizationService.getOrganizationByMrn(mrn);
            case "user" -> userService.getByMrn(mrn);
            case "vessel" -> vesselService.getByMrn(mrn);
            default -> null;
        };

        if (entity == null && "service".equals(type)) {
            List<Service> services = serviceService.getServicesByMrn(mrn);
            StringBuilder stringBuilder = new StringBuilder();
            for (Service service : services) {
                for (Certificate cert : service.getCertificates()) {
                    stringBuilder.append(cert.getCertificate());
                }
            }
            ret = stringBuilder.toString();
        } else if (entity != null) {
            StringBuilder stringBuilder = new StringBuilder();
            for (Certificate cert : entity.getCertificates()) {
                stringBuilder.append(cert.getCertificate());
            }
            ret = stringBuilder.toString();
        }
        return ret;
    }

    @Autowired
    public void setMrnUtil(MrnUtil mrnUtil) {
        this.mrnUtil = mrnUtil;
    }

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setDeviceService(DeviceServiceImpl deviceService) {
        this.deviceService = deviceService;
    }

    @Autowired
    public void setMmsService(MMSService mmsService) {
        this.mmsService = mmsService;
    }

    @Autowired
    public void setOrganizationService(OrganizationService organizationService) {
        this.organizationService = organizationService;
    }

    @Autowired
    public void setServiceService(ServiceService serviceService) {
        this.serviceService = serviceService;
    }

    @Autowired
    public void setUserService(EntityService<User> userService) {
        this.userService = userService;
    }

    @Autowired
    public void setVesselService(VesselServiceImpl vesselService) {
        this.vesselService = vesselService;
    }
}
