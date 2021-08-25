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
import net.maritimeconnectivity.identityregistry.model.data.CertificateBundle;
import net.maritimeconnectivity.identityregistry.model.data.CertificateRevocation;
import net.maritimeconnectivity.identityregistry.model.data.PemCertificate;
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
import net.maritimeconnectivity.pki.CertificateBuilder;
import net.maritimeconnectivity.pki.CertificateHandler;
import net.maritimeconnectivity.pki.PKIConstants;
import net.maritimeconnectivity.pki.pkcs11.P11PKIConfiguration;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
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

import javax.servlet.http.HttpServletRequest;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AuthProvider;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;

@Slf4j
@RestController
@RequestMapping(value={"oidc", "x509"})
public abstract class BaseControllerWithCertificate {

    @Autowired
    private CertificateService certificateService;

    @Autowired
    protected CertificateUtil certificateUtil;

    @Autowired
    protected MrnUtil mrnUtil;

    private final String[] insecureHashes = {"MD2", "MD4", "MD5", "SHA0", "SHA1"};

    /**
     * Function for generating key pair and certificate for an entity.
     *
     * @deprecated It is generally not considered secure letting the server generate the private key. Will be removed in the future
     *
     * @param certOwner the entity that the certificate belongs to
     * @param org the organization that the entity belongs to
     * @param type the entity type
     * @param request the HTTP request
     * @return a bundle containing certificate and key pair in different formats
     * @throws McpBasicRestException
     */
    @Deprecated
    protected CertificateBundle issueCertificate(CertificateModel certOwner, Organization org, String type, HttpServletRequest request) throws McpBasicRestException {
        AuthProvider authProvider = null;
        P11PKIConfiguration p11PKIConfiguration = null;
        if (certificateUtil.getPkiConfiguration() instanceof P11PKIConfiguration) {
            p11PKIConfiguration = (P11PKIConfiguration) certificateUtil.getPkiConfiguration();
            authProvider = p11PKIConfiguration.getProvider();
            p11PKIConfiguration.providerLogin();
        }
        // Generate keypair for user
        KeyPair userKeyPair = CertificateBuilder.generateKeyPair(authProvider);
        // Find special MC attributes to put in the certificate
        HashMap<String, String> attrs = getAttr(certOwner);

        String o = org.getMrn();
        String name = getName(certOwner);
        String email = getEmail(certOwner);
        String uid = getUid(certOwner);
        int validityPeriod = certificateUtil.getValidityPeriod(type);
        if(validityPeriod<0)
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.INVALID_MCP_TYPE, request.getServletPath());

        if (uid == null || uid.trim().isEmpty()) {
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.ENTITY_ORG_ID_MISSING, request.getServletPath());
        }
        BigInteger serialNumber = certificateUtil.getCertificateBuilder().generateSerialNumber(authProvider);
        X509Certificate userCert;
        try {
            if (authProvider != null) {
                userCert = certificateUtil.getCertificateBuilder().generateCertForEntity(serialNumber, org.getCountry(), o, type, name, email, uid, validityPeriod, userKeyPair.getPublic(), attrs, org.getCertificateAuthority(), certificateUtil.getBaseCrlOcspCrlURI(), authProvider);
            } else {
                userCert = certificateUtil.getCertificateBuilder().generateCertForEntity(serialNumber, org.getCountry(), o, type, name, email, uid, validityPeriod, userKeyPair.getPublic(), attrs, org.getCertificateAuthority(), certificateUtil.getBaseCrlOcspCrlURI(), null);
            }
        } catch (Exception e) {
            log.error(MCPIdRegConstants.CERT_ISSUING_FAILED, e);
            throw new McpBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCPIdRegConstants.CERT_ISSUING_FAILED, request.getServletPath());
        }
        String pemCertificate;
        try {
            pemCertificate = CertificateHandler.getPemFromEncoded("CERTIFICATE", userCert.getEncoded()).replace("\n", "\\n");
        } catch (CertificateEncodingException e) {
            log.error(MCPIdRegConstants.CERT_ISSUING_FAILED, e);
            throw new McpBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCPIdRegConstants.CERT_ISSUING_FAILED, request.getServletPath());
        }
        String pemPublicKey = CertificateHandler.getPemFromEncoded("PUBLIC KEY", userKeyPair.getPublic().getEncoded()).replace("\n", "\\n");
        String pemPrivateKey = CertificateHandler.getPemFromEncoded("PRIVATE KEY", userKeyPair.getPrivate().getEncoded()).replace("\n", "\\n");
        PemCertificate ret = new PemCertificate(pemPrivateKey, pemPublicKey, pemCertificate);

        // create the JKS and PKCS12 keystores and pack them in a bundle with the PEM certificate
        String keystorePassword = PasswordUtil.generatePassword(authProvider);
        if (authProvider != null) {
            p11PKIConfiguration.providerLogout();
        }
        byte[] jksKeystore = CertificateHandler.createOutputKeystore("JKS", name, keystorePassword, userKeyPair.getPrivate(), userCert);
        byte[] pkcs12Keystore = CertificateHandler.createOutputKeystore("PKCS12", name, keystorePassword, userKeyPair.getPrivate(), userCert);
        Base64.Encoder encoder = Base64.getEncoder();
        CertificateBundle certificateBundle = new CertificateBundle(ret, new String(encoder.encode(jksKeystore), StandardCharsets.UTF_8), new String(encoder.encode(pkcs12Keystore), StandardCharsets.UTF_8), keystorePassword);

        // Create the certificate
        Certificate newMCCert = new Certificate();
        certOwner.assignToCert(newMCCert);
        newMCCert.setCertificate(pemCertificate);
        newMCCert.setSerialNumber(serialNumber);
        newMCCert.setCertificateAuthority(org.getCertificateAuthority());
        // The dates we extract from the cert is in localtime, so they are converted to UTC before saving into the DB
        Calendar cal = Calendar.getInstance();
        int offset = cal.get(Calendar.ZONE_OFFSET) + cal.get(Calendar.DST_OFFSET);
        newMCCert.setStart(new Date(userCert.getNotBefore().getTime() - offset));
        newMCCert.setEnd(new Date(userCert.getNotAfter().getTime() - offset));
        this.certificateService.saveCertificate(newMCCert);
        return certificateBundle;
    }

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
                if (certificateUtil.getPkiConfiguration() instanceof P11PKIConfiguration) {
                    p11PKIConfiguration = (P11PKIConfiguration) certificateUtil.getPkiConfiguration();
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
                if(validityPeriod < 0)
                    throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.INVALID_MCP_TYPE, request.getServletPath());

                if (uid == null || uid.trim().isEmpty()) {
                    throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.ENTITY_ORG_ID_MISSING, request.getServletPath());
                }
                BigInteger serialNumber = certificateUtil.getCertificateBuilder().generateSerialNumber(authProvider);
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
                String pemCertificate;
                try {
                    pemCertificate = CertificateHandler.getPemFromEncoded("CERTIFICATE", userCert.getEncoded());

                    // Create the certificate
                    Certificate newMCCert = new Certificate();
                    certOwner.assignToCert(newMCCert);
                    newMCCert.setCertificate(pemCertificate);
                    newMCCert.setSerialNumber(serialNumber);
                    newMCCert.setCertificateAuthority(org.getCertificateAuthority());
                    // The dates we extract from the cert is in localtime, so they are converted to UTC before saving into the DB
                    Calendar cal = Calendar.getInstance();
                    int offset = cal.get(Calendar.ZONE_OFFSET) + cal.get(Calendar.DST_OFFSET);
                    newMCCert.setStart(new Date(userCert.getNotBefore().getTime() - offset));
                    newMCCert.setEnd(new Date(userCert.getNotAfter().getTime() - offset));
                    this.certificateService.saveCertificate(newMCCert);

                    byte[] certCA = this.certificateUtil.getKeystoreHandler().getMCPCertificate(org.getCertificateAuthority()).getEncoded();
                    String certCAPem = CertificateHandler.getPemFromEncoded("CERTIFICATE", certCA);

                    Certificate ret = new Certificate();
                    ret.setCertificate(pemCertificate + certCAPem);
                    ret.setSerialNumber(serialNumber);

                    return ret;
                } catch (CertificateEncodingException e) {
                    log.error(MCPIdRegConstants.CERT_ISSUING_FAILED, e);
                    throw new McpBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCPIdRegConstants.CERT_ISSUING_FAILED, request.getServletPath());
                }
            }
        } catch (PKCSException e) {
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.CSR_SIGNATURE_INVALID, request.getServletPath());
        }
        throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.CSR_SIGNATURE_INVALID, request.getServletPath());
    }

    private void checkSignatureAlgorithm(JcaPKCS10CertificationRequest csr, HttpServletRequest request) throws McpBasicRestException {
        DefaultAlgorithmNameFinder algorithmNameFinder = new DefaultAlgorithmNameFinder();
        String algoName = algorithmNameFinder.getAlgorithmName(csr.getSignatureAlgorithm());
        for (String insecureHash : this.insecureHashes) {
            if (algoName.contains(insecureHash)) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.WEAK_HASH, request.getServletPath());
            }
        }
    }

    private void checkPublicKey(PublicKey publicKey, HttpServletRequest request) throws McpBasicRestException {
        String algorithm;
        int keyLength;
        if (publicKey instanceof RSAPublicKey) {
            keyLength = ((RSAPublicKey) publicKey).getModulus().bitLength();
            algorithm = "RSA";
        } else if (publicKey instanceof ECPublicKey) {
            keyLength = ((ECPublicKey) publicKey).getParams().getCurve().getField().getFieldSize();
            algorithm = "EC";
        } else if (publicKey instanceof DSAPublicKey) {
            keyLength = ((DSAPublicKey) publicKey).getParams().getP().bitLength();
            algorithm = "DSA";
        } else if (publicKey instanceof BCEdDSAPublicKey) {
            keyLength = 256;
            algorithm = "EdDSA";
        } else {
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.PUBLIC_KEY_INVALID, request.getServletPath());
        }

        if ((algorithm.equals("RSA") || algorithm.equals("DSA")) && keyLength < 2048) {
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.RSA_KEY_TOO_SHORT, request.getServletPath());
        } else if ((algorithm.equals("EC") || algorithm.equals("EdDSA")) && keyLength < 224) {
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
        cert.setRevokeReason(input.getRevokationReason());
        cert.setRevoked(true);
        this.certificateService.saveCertificate(cert);
    }

    /* Override if the entity type of the controller isn't of type NonHumanEntityModel */
    protected String getName(CertificateModel certOwner) {
        return ((NonHumanEntityModel)certOwner).getName();
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
}
