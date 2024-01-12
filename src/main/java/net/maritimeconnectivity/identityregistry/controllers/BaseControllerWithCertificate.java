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

import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.identityregistry.exception.McpBasicRestException;
import net.maritimeconnectivity.identityregistry.model.data.CertificateRevocation;
import net.maritimeconnectivity.identityregistry.model.database.Certificate;
import net.maritimeconnectivity.identityregistry.model.database.CertificateModel;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.model.database.entities.EntityModel;
import net.maritimeconnectivity.identityregistry.model.database.entities.NonHumanEntityModel;
import net.maritimeconnectivity.identityregistry.services.CertificateService;
import net.maritimeconnectivity.identityregistry.utils.CertificateUtil;
import net.maritimeconnectivity.identityregistry.utils.MCPIdRegConstants;
import net.maritimeconnectivity.identityregistry.utils.MrnUtil;
import net.maritimeconnectivity.identityregistry.utils.PasswordUtil;
import net.maritimeconnectivity.pki.CertificateHandler;
import net.maritimeconnectivity.pki.PKIConstants;
import net.maritimeconnectivity.pki.pkcs11.P11PKIConfiguration;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AuthProvider;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.HashMap;

@Slf4j
@RestController
@RequestMapping(value = {"oidc", "x509"})
public abstract class BaseControllerWithCertificate {

    private enum SignatureAlgorithm {
        RSA, DSA, ECDSA, EDDSA
    }

    protected CertificateService certificateService;

    protected CertificateUtil certificateUtil;

    protected PasswordUtil passwordUtil;

    protected MrnUtil mrnUtil;

    private static final String[] INSECURE_HASHES = {"MD2", "MD4", "MD5", "SHA0", "SHA1"};

    protected Certificate signCertificate(JcaPKCS10CertificationRequest csr, CertificateModel certOwner, Organization org, String type, HttpServletRequest request) throws McpBasicRestException {
        PublicKey publicKey;
        try {
            publicKey = csr.getPublicKey();
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.PUBLIC_KEY_INVALID, request.getServletPath());
        }
        // check if public key is long enough
        this.checkPublicKey(publicKey, request);
        // check if csr uses an insecure signature algorithm
        this.checkSignatureAlgorithm(csr, request);

        JcaContentVerifierProviderBuilder contentVerifierProviderBuilder = new JcaContentVerifierProviderBuilder();
        ContentVerifierProvider contentVerifierProvider;
        try {
            contentVerifierProvider = contentVerifierProviderBuilder.build(publicKey);
        } catch (OperatorCreationException e) {
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.PUBLIC_KEY_INVALID, request.getServletPath());
        }
        try {
            if (csr.isSignatureValid(contentVerifierProvider)) {
                AuthProvider authProvider = null;
                P11PKIConfiguration p11PKIConfiguration = null;
                if (certificateUtil.getPkiConfiguration() instanceof P11PKIConfiguration p11) {
                    p11PKIConfiguration = p11;
                    authProvider = p11PKIConfiguration.getProvider();
                    p11PKIConfiguration.providerLogin();
                }
                // Find special MC attributes to put in the certificate
                HashMap<String, String> attrs = getAttr(certOwner);

                String o = org.getMrn();
                String name = getName(certOwner);
                String email = getEmail(certOwner);
                String uid = getUid(certOwner);
                int validityPeriod = certificateUtil.getValidityPeriod(type);
                if (validityPeriod < 0)
                    throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.INVALID_MCP_TYPE, request.getServletPath());

                if (uid == null || uid.trim().isEmpty()) {
                    throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.ENTITY_ORG_ID_MISSING, request.getServletPath());
                }

                BigInteger serialNumber = null;

                // Make sure that the serial number is unique
                do {
                    serialNumber = certificateUtil.getCertificateBuilder().generateSerialNumber(p11PKIConfiguration);
                } while (this.certificateService.countCertificatesBySerialNumber(serialNumber) != 0);
                X509Certificate userCert = createX509Certificate(org, type, request, publicKey, authProvider, p11PKIConfiguration, attrs, o, name, email, uid, validityPeriod, serialNumber);
                return createCertificate(certOwner, org, request, serialNumber, userCert);
            }
        } catch (PKCSException e) {
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.CSR_SIGNATURE_INVALID, request.getServletPath());
        }
        throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.CSR_SIGNATURE_INVALID, request.getServletPath());
    }

    private X509Certificate createX509Certificate(Organization org, String type, HttpServletRequest request, PublicKey publicKey, AuthProvider authProvider, P11PKIConfiguration p11PKIConfiguration, HashMap<String, String> attrs, String o, String name, String email, String uid, int validityPeriod, BigInteger serialNumber) throws McpBasicRestException {
        X509Certificate userCert;
        try {
            if (authProvider != null) {
                userCert = certificateUtil.getCertificateBuilder().generateCertForEntity(serialNumber, org.getCountry(), o, type, name, email, uid, validityPeriod, publicKey, attrs, org.getCertificateAuthority(), certificateUtil.getBaseCrlOcspCrlURI(), authProvider);
                p11PKIConfiguration.providerLogout();
            } else {
                userCert = certificateUtil.getCertificateBuilder().generateCertForEntity(serialNumber, org.getCountry(), o, type, name, email, uid, validityPeriod, publicKey, attrs, org.getCertificateAuthority(), certificateUtil.getBaseCrlOcspCrlURI(), null);
            }
        } catch (Exception e) {
            log.error(MCPIdRegConstants.CERT_ISSUING_FAILED, e);
            throw new McpBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCPIdRegConstants.CERT_ISSUING_FAILED, request.getServletPath());
        }
        return userCert;
    }

    private Certificate createCertificate(CertificateModel certOwner, Organization org, HttpServletRequest request, BigInteger serialNumber, X509Certificate userCert) throws McpBasicRestException {
        String pemCertificate;
        try {
            pemCertificate = CertificateHandler.getPemFromEncoded("CERTIFICATE", userCert.getEncoded());

            // Create the certificate
            Certificate newMCCert = new Certificate();
            certOwner.assignToCert(newMCCert);
            newMCCert.setCertificate(pemCertificate);
            newMCCert.setSerialNumber(serialNumber);
            newMCCert.setThumbprint(computeB64Thumbprint(userCert));
            newMCCert.setCertificateAuthority(org.getCertificateAuthority());
            newMCCert.setStart(userCert.getNotBefore());
            newMCCert.setEnd(userCert.getNotAfter());
            this.certificateService.saveCertificate(newMCCert);

            byte[] certCA = this.certificateUtil.getKeystoreHandler().getMCPCertificate(org.getCertificateAuthority()).getEncoded();
            String certCAPem = CertificateHandler.getPemFromEncoded("CERTIFICATE", certCA);

            Certificate ret = new Certificate();
            ret.setCertificate(pemCertificate + certCAPem);
            ret.setSerialNumber(serialNumber);

            return ret;
        } catch (CertificateEncodingException | IOException e) {
            log.error(MCPIdRegConstants.CERT_ISSUING_FAILED, e);
            throw new McpBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCPIdRegConstants.CERT_ISSUING_FAILED, request.getServletPath());
        }
    }

    private String computeB64Thumbprint(X509Certificate userCert) throws CertificateEncodingException {
        byte[] encodedDigest;
        // If we are using an HSM we might as well try to use that to compute the thumbprint of the certificate
        if (certificateUtil.isUsingPKCS11()) {
            P11PKIConfiguration p11PKIConfiguration = (P11PKIConfiguration) certificateUtil.getPkiConfiguration();
            try {
                p11PKIConfiguration.providerLogin();
                MessageDigest digest = MessageDigest.getInstance("SHA-256", p11PKIConfiguration.getPkcs11ProviderName());
                encodedDigest = digest.digest(userCert.getEncoded());
            } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                log.warn("Could not get SHA-256 provider for HSM, falling back to BC");
                MessageDigest digest = new SHA256.Digest();
                encodedDigest = digest.digest(userCert.getEncoded());
            } finally {
                p11PKIConfiguration.providerLogout();
            }
        } else {
            MessageDigest digest = new SHA256.Digest();
            encodedDigest = digest.digest(userCert.getEncoded());
        }
        return Base64.getEncoder().encodeToString(encodedDigest);
    }

    private void checkSignatureAlgorithm(JcaPKCS10CertificationRequest csr, HttpServletRequest request) throws McpBasicRestException {
        DefaultAlgorithmNameFinder algorithmNameFinder = new DefaultAlgorithmNameFinder();
        String algoName = algorithmNameFinder.getAlgorithmName(csr.getSignatureAlgorithm());
        for (String insecureHash : INSECURE_HASHES) {
            if (algoName.contains(insecureHash)) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.WEAK_HASH, request.getServletPath());
            }
        }
    }

    private void checkPublicKey(PublicKey publicKey, HttpServletRequest request) throws McpBasicRestException {
        SignatureAlgorithm algorithm;
        int keyLength;
        if (publicKey instanceof RSAPublicKey rsaPublicKey) {
            keyLength = rsaPublicKey.getModulus().bitLength();
            algorithm = SignatureAlgorithm.RSA;
        } else if (publicKey instanceof ECPublicKey ecPublicKey) {
            keyLength = ecPublicKey.getParams().getCurve().getField().getFieldSize();
            algorithm = SignatureAlgorithm.ECDSA;
        } else if (publicKey instanceof DSAPublicKey dsaPublicKey) {
            keyLength = dsaPublicKey.getParams().getP().bitLength();
            algorithm = SignatureAlgorithm.DSA;
        } else if ("EdDSA".equals(publicKey.getAlgorithm())) {
            keyLength = 256;
            algorithm = SignatureAlgorithm.EDDSA;
        } else {
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.PUBLIC_KEY_INVALID, request.getServletPath());
        }

        if ((algorithm.equals(SignatureAlgorithm.RSA) || algorithm.equals(SignatureAlgorithm.DSA)) && keyLength < 2048) {
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.RSA_KEY_TOO_SHORT, request.getServletPath());
        } else if ((algorithm.equals(SignatureAlgorithm.ECDSA) || algorithm.equals(SignatureAlgorithm.EDDSA)) && keyLength < 224) {
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.EC_KEY_TOO_SHORT, request.getServletPath());
        }
    }

    protected void revokeCertificate(BigInteger certId, CertificateRevocation input, HttpServletRequest request) throws McpBasicRestException {
        Certificate cert = this.certificateService.getCertificateBySerialNumber(certId);
        if (!input.validateReason()) {
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.INVALID_REVOCATION_REASON, request.getServletPath());
        }
        if (input.getRevokedAt() == null) {
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.INVALID_REVOCATION_DATE, request.getServletPath());
        }
        cert.setRevokedAt(input.getRevokedAt());
        cert.setRevokeReason(input.getRevocationReason());
        cert.setRevoked(true);
        this.certificateService.saveCertificate(cert);
    }

    /* Override if the entity type of the controller isn't of type NonHumanEntityModel */

    protected String getName(CertificateModel certOwner) {
        return ((NonHumanEntityModel) certOwner).getName();
    }
    /* Override if the entity type of the controller isn't of type NonHumanEntityModel */

    protected abstract String getUid(CertificateModel certOwner);
    /* Override if the entity type of the controller has an email */

    protected String getEmail(CertificateModel certOwner) {
        return "";
    }
    /* Override if the entity type isn't of type EntityModel */

    protected HashMap<String, String> getAttr(CertificateModel certOwner) {
        HashMap<String, String> attrs = new HashMap<>();
        EntityModel entity = (EntityModel) certOwner;
        if (entity.getMrn() != null) {
            attrs.put(PKIConstants.MC_OID_MRN, entity.getMrn());
        }
        if (entity.getPermissions() != null) {
            attrs.put(PKIConstants.MC_OID_PERMISSIONS, entity.getPermissions());
        }
        if (entity.getMrnSubsidiary() != null) {
            attrs.put(PKIConstants.MC_OID_MRN_SUBSIDIARY, entity.getMrnSubsidiary());
        }
        if (entity.getHomeMMSUrl() != null) {
            attrs.put(PKIConstants.MC_OID_HOME_MMS_URL, entity.getHomeMMSUrl());
        }
        return attrs;
    }

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setCertificateUtil(CertificateUtil certificateUtil) {
        this.certificateUtil = certificateUtil;
    }

    @Autowired
    public void setPasswordUtil(PasswordUtil passwordUtil) {
        this.passwordUtil = passwordUtil;
    }

    @Autowired
    public void setMrnUtil(MrnUtil mrnUtil) {
        this.mrnUtil = mrnUtil;
    }
}
