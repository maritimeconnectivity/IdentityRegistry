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

import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.identityregistry.model.database.Certificate;
import net.maritimeconnectivity.identityregistry.services.CertificateService;
import net.maritimeconnectivity.identityregistry.utils.MrnUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigInteger;
import java.util.regex.Pattern;

@RestController
@RequestMapping(value = "/secom/v1")
@Slf4j
public class SecomController {

    private MrnUtil mrnUtil;

    private CertificateService certificateService;

    private final Pattern base64Pattern = Pattern.compile("^[-A-Za-z0-9+=]{1,50}|=[^=]|={3,}$");
    private final Pattern serialNumberPattern = Pattern.compile("^\\d+$");

    @GetMapping(
            value = "/publicKey/{parameter}",
            produces = "application/x-pem-file"
    )
    public ResponseEntity<String> getPublicKey(@PathVariable String parameter) {
        String ret = null;
        // check if the parameter is certificate thumbprint
        if (base64Pattern.matcher(parameter).matches()) {
            Certificate certificate = certificateService.getCertificateByThumbprint(parameter);
            if (certificate != null) {
                ret = certificate.getCertificate();
            }
        } else if (serialNumberPattern.matcher(parameter).matches()) {
            BigInteger serialNumber = new BigInteger(parameter);
            Certificate certificate = certificateService.getCertificateBySerialNumber(serialNumber);
            if (certificate != null) {
                ret = certificate.getCertificate();
            }
        } else if (mrnUtil.mcpMrnPattern.matcher(parameter).matches()) {

        }

        if (ret != null) {
            return ResponseEntity.ok(ret);
        }
        return ResponseEntity.notFound().build();
    }

    @Autowired
    public void setMrnUtil(MrnUtil mrnUtil) {
        this.mrnUtil = mrnUtil;
    }

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }
}
