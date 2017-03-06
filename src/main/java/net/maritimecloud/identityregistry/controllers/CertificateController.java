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
package net.maritimecloud.identityregistry.controllers;

import lombok.extern.slf4j.Slf4j;
import net.maritimecloud.identityregistry.model.database.Certificate;
import net.maritimecloud.identityregistry.services.CertificateService;
import net.maritimecloud.identityregistry.utils.CertificateUtil;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.List;

@RestController
@RequestMapping(value={"oidc", "x509"})
@Slf4j
public class CertificateController {
    private CertificateService certificateService;

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    private CertificateUtil certUtil;

    /**
     * Returns info about the device identified by the given ID
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/certificates/crl",
            method = RequestMethod.GET,
            produces = "application/x-pem-file;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<?> getCRL() {
        List<Certificate> revokedCerts = this.certificateService.listRevokedCertificate();
        X509CRL crl = certUtil.generateCRL(revokedCerts);
        try {
            String pemCrl = CertificateUtil.getPemFromEncoded("X509 CRL", crl.getEncoded());
            return new ResponseEntity<>(pemCrl, HttpStatus.OK);
        } catch (CRLException e) {
            log.error("Unable to get Pem from bytes", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @RequestMapping(
            value = "/api/certificates/ocsp",
            method = RequestMethod.POST,
            consumes = "application/ocsp-request",
            produces = "application/ocsp-response")
    @ResponseBody
    public ResponseEntity<?> postOCSP(@RequestBody byte[] input) {
        byte[] byteResponse;
        try {
            byteResponse = handleOCSP(input);
        } catch (IOException e) {
            log.error("Failed to update OCSP", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(byteResponse, HttpStatus.OK);
    }

    @RequestMapping(
            value = "/api/certificates/ocsp/{encodedOCSP}",
            method = RequestMethod.GET,
            produces = "application/ocsp-response")
    @ResponseBody
    public ResponseEntity<?> getOCSP(@PathVariable String encodedOCSP) {
        byte[] byteResponse;
        try {
            byteResponse = handleOCSP(Base64.decode(encodedOCSP));
        } catch (IOException e) {
            log.error("Failed to get OCSP", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(byteResponse, HttpStatus.OK);
    }

    private byte[] handleOCSP(byte[] input) throws IOException {
        OCSPReq ocspreq = new OCSPReq(input);
        if (ocspreq.isSigned()) {
            // TODO: verify signature - needed?
        }
        BasicOCSPRespBuilder respBuilder = certUtil.initOCSPRespBuilder(ocspreq);
        Req[] requests = ocspreq.getRequestList();
        for (Req req : requests) {
            BigInteger sn = req.getCertID().getSerialNumber();
            Certificate cert = this.certificateService.getCertificateById(sn.longValue());
            if (cert == null) {
                // Throw exception?
                continue;
            }
            // Check if certificate has been revoked
            if (cert.isRevoked()) {
                respBuilder.addResponse(req.getCertID(), new RevokedStatus(cert.getRevokedAt(), certUtil.getCRLReasonFromString(cert.getRevokeReason())));
            } else {
                // Certificate is valid
                respBuilder.addResponse(req.getCertID(), CertificateStatus.GOOD);
            }
        }
        OCSPResp response = certUtil.generateOCSPResponse(respBuilder);
        return response.getEncoded();
    }
}
