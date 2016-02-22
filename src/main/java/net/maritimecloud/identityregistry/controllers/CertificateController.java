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

import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import net.maritimecloud.identityregistry.model.Certificate;
import net.maritimecloud.identityregistry.services.CertificateService;
import net.maritimecloud.identityregistry.utils.CertificateUtil;

@RestController
@RequestMapping(value={"admin", "oidc", "x509"})
public class CertificateController {
    private CertificateService certificateService;

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

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
    public ResponseEntity<?> getCRL(HttpServletRequest request) {
        List<Certificate> revokedCerts = this.certificateService.listRevokedCertificate();
        X509CRL crl = CertificateUtil.generateCRL(revokedCerts);
        String pemCrl = "";
        try {
            pemCrl = CertificateUtil.getPemFromEncoded("X509 CRL", crl.getEncoded());
        } catch (CRLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<String>(pemCrl, HttpStatus.OK);
    }
}
