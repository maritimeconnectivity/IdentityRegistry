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

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.identityregistry.model.database.Certificate;
import net.maritimeconnectivity.identityregistry.services.CertificateService;
import net.maritimeconnectivity.identityregistry.utils.CertificateUtil;
import net.maritimeconnectivity.pki.CertificateHandler;
import net.maritimeconnectivity.pki.Revocation;
import net.maritimeconnectivity.pki.RevocationInfo;
import net.maritimeconnectivity.pki.pkcs11.P11PKIConfiguration;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.AuthProvider;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping(value = {"oidc", "x509"})
@Slf4j
public class CertificateController {
    private CertificateService certificateService;

    private CertificateUtil certUtil;

    /**
     * Get the CRL of the specified CA
     *
     * @return a reply...
     */
    @GetMapping(
            value = "/api/certificates/crl/{caAlias}",
            produces = "application/x-pem-file"
    )
    @Operation(
            description = "Get the CRL of the specified CA"
    )
    public ResponseEntity<String> getCRL(@PathVariable String caAlias) {
        // If looking for the root CRL we load that from a file and return it.
        if (certUtil.getRootCAAlias().equals(caAlias)) {
            try {
                String rootCrl = Files.readString(Paths.get(certUtil.getRootCrlPath()));
                return new ResponseEntity<>(rootCrl, HttpStatus.OK);
            } catch (IOException e) {
                log.error("Unable to load root crl file", e);
                return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
            }
        }
        X509Certificate caCert = (X509Certificate) certUtil.getKeystoreHandler().getMCPCertificate(caAlias);
        if (caCert == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        List<Certificate> revokedCerts = this.certificateService.listRevokedCertificate(caAlias);
        List<RevocationInfo> revocationInfos = new ArrayList<>();
        for (Certificate cert : revokedCerts) {
            revocationInfos.add(cert.toRevocationInfo());
        }
        AuthProvider provider = null;
        P11PKIConfiguration p11PKIConfiguration = null;
        if (certUtil.getPkiConfiguration() instanceof P11PKIConfiguration p11) {
            p11PKIConfiguration = p11;
            provider = p11PKIConfiguration.getProvider();
            p11PKIConfiguration.providerLogin();
        }
        X509CRL crl = Revocation.generateCRL(revocationInfos, certUtil.getKeystoreHandler().getSigningCertEntry(caAlias), p11PKIConfiguration);
        if (provider != null) {
            p11PKIConfiguration.providerLogout();
        }
        try {
            String pemCrl = CertificateHandler.getPemFromEncoded("X509 CRL", crl.getEncoded());
            return new ResponseEntity<>(pemCrl, HttpStatus.OK);
        } catch (CRLException | IOException e) {
            log.error("Unable to get PEM from bytes", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping(
            value = "/api/certificates/ocsp/{caAlias}",
            consumes = "application/ocsp-request",
            produces = "application/ocsp-response"
    )
    @Operation(
            description = "POST mapping for OCSP",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "OCSP request that is encoded as defined in RFC 6960 Appendix A.1")
    )
    public ResponseEntity<byte[]> postOCSP(@PathVariable String caAlias, @RequestBody byte[] input) {
        return generateOCSPResponseEntity(caAlias, input);
    }

    @GetMapping(
            value = "/api/certificates/ocsp/{caAlias}/{ocspRequest}",
            produces = "application/ocsp-response"
    )
    @Operation(
            description = "GET mapping for OCSP"
    )
    public ResponseEntity<byte[]> getOCSP(@PathVariable String caAlias, @Parameter(description = "OCSP request that is encoded as defined in RFC 6960 Appendix A.1") @PathVariable String ocspRequest) {
        byte[] decodedOCSP = Base64.decode(ocspRequest);
        return generateOCSPResponseEntity(caAlias, decodedOCSP);
    }

    private ResponseEntity<byte[]> generateOCSPResponseEntity(String caAlias, byte[] input) {
        byte[] byteResponse;
        try {
            byteResponse = handleOCSP(input, caAlias);
        } catch (IOException e) {
            log.error("Failed to generate OCSP response", e);
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(byteResponse, HttpStatus.OK);
    }

    protected byte[] handleOCSP(byte[] input, String certAlias) throws IOException {
        OCSPReq ocspreq;
        try {
            ocspreq = new OCSPReq(input);
        } catch (IOException e) {
            log.error("Received a malformed OCSP request", e);
            OCSPResponse ocspResponse = new OCSPResponse(new OCSPResponseStatus(OCSPResponseStatus.MALFORMED_REQUEST), null);
            return new OCSPResp(ocspResponse).getEncoded();
        }
        Map<CertificateID, CertificateStatus> certificateStatusMap = new HashMap<>();
        Req[] requests = ocspreq.getRequestList();
        for (Req req : requests) {
            BigInteger serialNumber = req.getCertID().getSerialNumber();
            Certificate cert = this.certificateService.getCertificateBySerialNumber(serialNumber);

            if (cert == null || !certAlias.equals(cert.getCertificateAuthority())) {
                certificateStatusMap.put(req.getCertID(), new UnknownStatus());
                // Check if certificate has been revoked
            } else if (cert.isRevoked()) {
                certificateStatusMap.put(req.getCertID(), new RevokedStatus(cert.getRevokedAt(), Revocation.getCRLReasonFromString(cert.getRevokeReason())));
            } else {
                // Certificate is valid
                certificateStatusMap.put(req.getCertID(), CertificateStatus.GOOD);
            }
        }

        PublicKey caPublicKey = certUtil.getKeystoreHandler().getMCPCertificate(certAlias).getPublicKey();
        KeyStore.PrivateKeyEntry caKeystoreEntry = certUtil.getKeystoreHandler().getSigningCertEntry(certAlias);
        OCSPResp response = Revocation.handleOCSP(ocspreq, caPublicKey, caKeystoreEntry, certificateStatusMap, certUtil.getPkiConfiguration());
        return response.getEncoded();
    }

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setCertUtil(CertificateUtil certUtil) {
        this.certUtil = certUtil;
    }
}
