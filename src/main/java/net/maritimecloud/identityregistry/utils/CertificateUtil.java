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
package net.maritimecloud.identityregistry.utils;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DERUniversalString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.stereotype.Component;
import org.bouncycastle.jce.X509KeyUsage;

@Component
public class CertificateUtil {

    private static final Logger logger = LoggerFactory.getLogger(CertificateUtil.class);

    public static final int CERT_EXPIRE_YEAR = 2025;
    public static final String ROOT_CERT_ALIAS = "rootcert";
    public static final String INTERMEDIATE_CERT_ALIAS = "imcert";
    public static final String BC_PROVIDER_NAME = "BC";
    public static final String KEYSTORE_TYPE = "jks";
    public static final String SIGNER_ALGORITHM = "SHA256withECDSA";

    // Values below are loaded from application.yaml
    @Value("${net.maritimecloud.idreg.certs.mcidreg-cert-x500-name}")
    public String MCIDREG_CERT_X500_NAME;

    @Value("${net.maritimecloud.idreg.certs.crl-url}")
    private String CRL_URL;

    @Value("${net.maritimecloud.idreg.certs.ocsp-url}")
    private String OCSP_URL;

    @Value("${net.maritimecloud.idreg.certs.root-keystore}")
    private String ROOT_KEYSTORE_PATH;

    @Value("${net.maritimecloud.idreg.certs.it-keystore}")
    private String INTERMEDIATE_KEYSTORE_PATH;

    @Value("${net.maritimecloud.idreg.certs.keystore-password}")
    private String KEYSTORE_PASSWORD;

    @Value("${net.maritimecloud.idreg.certs.truststore}")
    private String TRUSTSTORE_PATH;

    @Value("${net.maritimecloud.idreg.certs.truststore-password}")
    private String TRUSTSTORE_PASSWORD;

    // OIDs used for the extra info stored in the SubjectAlternativeName extension
    // Generate more random OIDs at http://www.itu.int/en/ITU-T/asn1/Pages/UUID/generate_uuid.aspx
    public static final String MC_OID_FLAGSTATE        = "2.25.323100633285601570573910217875371967771";
    public static final String MC_OID_CALLSIGN         = "2.25.208070283325144527098121348946972755227";
    public static final String MC_OID_IMO_NUMBER       = "2.25.291283622413876360871493815653100799259";
    public static final String MC_OID_MMSI_NUMBER      = "2.25.328433707816814908768060331477217690907";
    // See http://www.shipais.com/doc/Pifaq/1/22/ and https://help.marinetraffic.com/hc/en-us/articles/205579997-What-is-the-significance-of-the-AIS-SHIPTYPE-number-
    public static final String MC_OID_AIS_SHIPTYPE     = "2.25.107857171638679641902842130101018412315";
    public static final String MC_OID_MRN              = "2.25.271477598449775373676560215839310464283";
    public static final String MC_OID_PERMISSIONS      = "2.25.174437629172304915481663724171734402331";
    public static final String MC_OID_PORT_OF_REGISTER = "2.25.285632790821948647314354670918887798603";

    public CertificateUtil() {
    }

    /**
     * Builds and signs a certificate. The certificate will be build on the given subject-public-key and signed with
     * the given issuer-private-key. The issuer and subject will be identified in the strings provided.
     * 
     * @param signerPrivateKey
     * @param subjectPublicKey
     * @param issuer
     * @param subject
     * @return A signed X509Certificate
     * @throws Exception
     */
    public X509Certificate buildAndSignCert(Long serialNumber, PrivateKey signerPrivateKey, PublicKey signerPublicKey, PublicKey subjectPublicKey, X500Name issuer, X500Name subject,
                                                   Map<String, String> customAttrs, String type) throws Exception {
        // Dates are converted to GMT/UTC inside the cert builder 
        Calendar cal = Calendar.getInstance();
        Date now = cal.getTime();
        Date expire = new GregorianCalendar(CERT_EXPIRE_YEAR, 0, 1).getTime();
        X509v3CertificateBuilder certV3Bldr = new JcaX509v3CertificateBuilder(issuer,
                                                                                BigInteger.valueOf(serialNumber),
                                                                                now, // Valid from now...
                                                                                expire, // until CERT_EXPIRE_YEAR
                                                                                subject,
                                                                                subjectPublicKey);
        JcaX509ExtensionUtils extensionUtil = new JcaX509ExtensionUtils();
        // Create certificate extensions
        if ("ROOTCA".equals(type)) {
            certV3Bldr = certV3Bldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                                   .addExtension(Extension.keyUsage, true, new X509KeyUsage(X509KeyUsage.digitalSignature |
                                                                                            X509KeyUsage.nonRepudiation   |
                                                                                            X509KeyUsage.keyEncipherment  |
                                                                                            X509KeyUsage.keyCertSign      |
                                                                                            X509KeyUsage.cRLSign));
        } else if ("INTERMEDIATE".equals(type)) {
            certV3Bldr = certV3Bldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                                   .addExtension(Extension.keyUsage, true, new X509KeyUsage(X509KeyUsage.digitalSignature |
                                                                                            X509KeyUsage.nonRepudiation   |
                                                                                            X509KeyUsage.keyEncipherment  |
                                                                                            X509KeyUsage.keyCertSign      |
                                                                                            X509KeyUsage.cRLSign));
        } else {
            // Subject Alternative Name
            GeneralName[] genNames = null;
            if (customAttrs != null && !customAttrs.isEmpty()) {
                genNames = new GeneralName[customAttrs.size()];
                Iterator<Map.Entry<String,String>> it = customAttrs.entrySet().iterator();
                int idx = 0;
                while (it.hasNext()) {
                    Map.Entry<String,String> pair = (Map.Entry<String,String>)it.next();
                    //genNames[idx] = new GeneralName(GeneralName.otherName, new DERUTF8String(pair.getKey() + ";" + pair.getValue()));
                    DERSequence othernameSequence = new DERSequence(new ASN1Encodable[]{
                            new ASN1ObjectIdentifier(pair.getKey()), new DERTaggedObject(true, 0, new DERUTF8String(pair.getValue()))});
                    genNames[idx] = new GeneralName(GeneralName.otherName, othernameSequence);
                    idx++;
                }
            }
            if (genNames != null) {
                certV3Bldr = certV3Bldr.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(genNames));
            }
        }
        // Basic extension setup
        certV3Bldr = certV3Bldr.addExtension(Extension.authorityKeyIdentifier, false, extensionUtil.createAuthorityKeyIdentifier(signerPublicKey))
                               .addExtension(Extension.subjectKeyIdentifier, false, extensionUtil.createSubjectKeyIdentifier(subjectPublicKey));
        // CRL Distribution Points
        DistributionPointName distPointOne = new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, CRL_URL)));
        DistributionPoint[] distPoints = new DistributionPoint[1];
        distPoints[0] = new DistributionPoint(distPointOne, null, null);
        certV3Bldr.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distPoints));
        // OCSP endpoint
        GeneralName ocspName = new GeneralName(GeneralName.uniformResourceIdentifier, OCSP_URL);
        AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess(X509ObjectIdentifiers.ocspAccessMethod, ocspName);
        certV3Bldr.addExtension(Extension.authorityInfoAccess, false, authorityInformationAccess);
        // Create the key signer
        JcaContentSignerBuilder builder = new JcaContentSignerBuilder(SIGNER_ALGORITHM);
        builder.setProvider(BC_PROVIDER_NAME);
        ContentSigner signer = builder.build(signerPrivateKey);
        return new JcaX509CertificateConverter().setProvider(BC_PROVIDER_NAME).getCertificate(certV3Bldr.build(signer));
    }
    
    /**
     * Generates a self-signed certificate based on the keypair and saves it in the keystore.
     * Should only be used to init the CA.
     */
    public void initCA(String rootCertX500Name, String mcidregCertX500Name, String crlUrl, String ocspUrl) {
        if (KEYSTORE_PASSWORD == null) {
            KEYSTORE_PASSWORD = "changeit";
        }
        if (ROOT_KEYSTORE_PATH == null) {
            ROOT_KEYSTORE_PATH = "mc-root-keystore.jks";
        }
        if (INTERMEDIATE_KEYSTORE_PATH == null) {
            INTERMEDIATE_KEYSTORE_PATH = "mc-it-keystore.jks";
        }
        if (TRUSTSTORE_PASSWORD == null) {
            TRUSTSTORE_PASSWORD = "changeit";
        }
        if (TRUSTSTORE_PATH == null) {
            TRUSTSTORE_PATH = "mc-truststore.jks";
        }
        if (CRL_URL == null) {
            CRL_URL = crlUrl;
        }
        if (OCSP_URL == null) {
            OCSP_URL = ocspUrl;
        }
        KeyPair cakp = generateKeyPair();
        KeyPair imkp = generateKeyPair(); 
        KeyStore rootks;
        KeyStore itks;
        KeyStore ts;
        FileOutputStream rootfos = null;
        FileOutputStream itfos = null;
        FileOutputStream tsfos = null;
        try {
            rootks = KeyStore.getInstance(KEYSTORE_TYPE); // KeyStore.getDefaultType() 
            rootks.load(null, KEYSTORE_PASSWORD.toCharArray());
            itks = KeyStore.getInstance(KEYSTORE_TYPE); // KeyStore.getDefaultType() 
            itks.load(null, KEYSTORE_PASSWORD.toCharArray());
            // Store away the keystore.
            rootfos = new FileOutputStream(ROOT_KEYSTORE_PATH);
            itfos = new FileOutputStream(INTERMEDIATE_KEYSTORE_PATH);
            X509Certificate cacert;
            try {
                cacert = buildAndSignCert(Long.valueOf(0), cakp.getPrivate(), cakp.getPublic(), cakp.getPublic(),
                                          new X500Name(rootCertX500Name), new X500Name(rootCertX500Name), null, "ROOTCA");
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                return;
            }
            X509Certificate imcert;
            try {
                imcert = buildAndSignCert(Long.valueOf(0), cakp.getPrivate(), cakp.getPublic(), imkp.getPublic(),
                                          new X500Name(rootCertX500Name), new X500Name(mcidregCertX500Name), null, "INTERMEDIATE");
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                return;
            }
            Certificate[] certChain = new Certificate[1];
            certChain[0] = cacert;
            rootks.setKeyEntry(ROOT_CERT_ALIAS, cakp.getPrivate(), KEYSTORE_PASSWORD.toCharArray(), certChain);
            rootks.store(rootfos, KEYSTORE_PASSWORD.toCharArray());
            rootks = KeyStore.getInstance(KeyStore.getDefaultType());
            rootks.load(null, KEYSTORE_PASSWORD.toCharArray());
            
            certChain = new Certificate[2];
            certChain[0] = imcert;
            certChain[1] = cacert;
            itks.setKeyEntry(INTERMEDIATE_CERT_ALIAS, imkp.getPrivate(), KEYSTORE_PASSWORD.toCharArray(), certChain);
            itks.store(itfos, KEYSTORE_PASSWORD.toCharArray());
            
            // Store away the truststore.
            ts = KeyStore.getInstance(KeyStore.getDefaultType());
            ts.load(null, TRUSTSTORE_PASSWORD.toCharArray());
            tsfos = new FileOutputStream(TRUSTSTORE_PATH);
            ts.setCertificateEntry(ROOT_CERT_ALIAS, cacert);
            ts.setCertificateEntry(INTERMEDIATE_CERT_ALIAS, imcert);
            ts.store(tsfos, TRUSTSTORE_PASSWORD.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return;
        } finally {
            try {
                if (rootfos != null) {
                    rootfos.close();
                }
                if (itfos != null) {
                    itfos.close();
                }
                if (tsfos != null) {
                    tsfos.close();
                }
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }
    
    
    /**
     * Generates a keypair (public and private) based on Elliptic curves.
     * 
     * @return The generated keypair
     */
    public static KeyPair generateKeyPair() {
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp384r1");
        KeyPairGenerator g;
        try {
            g = KeyPairGenerator.getInstance("ECDSA", BC_PROVIDER_NAME);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return null;
        }
        try {
            g.initialize(ecGenSpec, new SecureRandom());
        } catch (InvalidAlgorithmParameterException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
        KeyPair pair = g.generateKeyPair();
        return pair;
    }
    
    
    /**
     * Loads the MaritimeCloud certificate used for signing from the keystore
     *  
     * @return
     */
    public PrivateKeyEntry getSigningCertEntry() {
        FileInputStream is;
        try {
            is = new FileInputStream(INTERMEDIATE_KEYSTORE_PATH);
        } catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
        KeyStore keystore;
        try {
            keystore = KeyStore.getInstance(KEYSTORE_TYPE);
            keystore.load(is, KEYSTORE_PASSWORD.toCharArray());
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(KEYSTORE_PASSWORD.toCharArray());
            PrivateKeyEntry signingCertEntry = (PrivateKeyEntry) keystore.getEntry(INTERMEDIATE_CERT_ALIAS, protParam);
            return signingCertEntry;
            
        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException | UnrecoverableEntryException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * Generates a signed certificate for an entity.
     * 
     * @param country The country of org/entity
     * @param orgName The name of the organization the entity belongs to
     * @param type The type of the  entity
     * @param callName The name of the entity
     * @param email The email of the entity
     * @param publickey The public key of the entity
     * @return Returns a signed X509Certificate
     */
    public X509Certificate generateCertForEntity(Long serialNumber, String country, String orgName, String type, String callName, String email, String uid, PublicKey publickey, Map<String, String> customAttr) {
        PrivateKeyEntry signingCertEntry = getSigningCertEntry();
        java.security.cert.Certificate signingCert = signingCertEntry.getCertificate();
        X509Certificate signingX509Cert = (X509Certificate) signingCert;
        // Try to find the correct country code, else we just use the country name as code
        String orgCountryCode = country;
        String[] locales = Locale.getISOCountries();
        for (String countryCode : locales) {
            Locale loc = new Locale("", countryCode);
            if (loc.getDisplayCountry(Locale.ENGLISH).equals(orgCountryCode)) {
                orgCountryCode = loc.getCountry();
                break;
            }
        }
        String orgSubjectDn = "C=" + orgCountryCode + ", " +
                              "O=" + orgName + ", " +
                              "OU=" + type + ", " +
                              "CN=" + callName + ", " +
                              "UID=" + uid;
        if (email != null && !email.isEmpty()) {
            orgSubjectDn += ", " + "E=" + email;
        }
        X509Certificate orgCert = null;
        try {
            orgCert = buildAndSignCert(serialNumber, signingCertEntry.getPrivateKey(), signingX509Cert.getPublicKey(),
                                       publickey, new JcaX509CertificateHolder(signingX509Cert).getSubject(), new X500Name(orgSubjectDn), customAttr, "ENTITY");
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return orgCert;
    }
    
    public int getCRLReasonFromString(String certReason) {
        int reason = CRLReason.unspecified;
        if ("unspecified".equals(certReason)) {
            reason = CRLReason.unspecified;
        } else if ("keycompromise".equals(certReason)) {
            reason = CRLReason.keyCompromise;
        } else if ("cacompromise".equals(certReason)) {
            reason = CRLReason.cACompromise;
        } else if ("affiliationchanged".equals(certReason)) {
            reason = CRLReason.affiliationChanged;
        } else if ("superseded".equals(certReason)) {
            reason = CRLReason.superseded;
        } else if ("cessationofoperation".equals(certReason)) {
            reason = CRLReason.cessationOfOperation;
        } else if ("certificateHold".equals(certReason)) {
            reason = CRLReason.certificateHold;
        } else if ("removefromcrl".equals(certReason)) {
            reason = CRLReason.removeFromCRL;
        } else if ("privilegewithdrawn".equals(certReason)) {
            reason = CRLReason.privilegeWithdrawn;
        } else if ("aacompromise".equals(certReason)) {
            reason = CRLReason.aACompromise;
        }
        return reason; 
    }
    
    /**
     * Creates a Certificate Revocation List (CRL) for the certificate serialnumbers given.
     * 
     * @param revokedCerts  List of the serialnumbers that should be revoked.
     * @return
     */
    public X509CRL generateCRL(List<net.maritimecloud.identityregistry.model.database.Certificate> revokedCerts) {
        Date now = new Date();
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(new X500Name(MCIDREG_CERT_X500_NAME), now);
        crlBuilder.setNextUpdate(new Date(now.getTime() + 24 * 60 * 60 * 1000)); // The next CRL is tomorrow (dummy value)
        for (net.maritimecloud.identityregistry.model.database.Certificate cert : revokedCerts) {
            String certReason = cert.getRevokeReason().toLowerCase();
            int reason = getCRLReasonFromString(certReason);
            crlBuilder.addCRLEntry(BigInteger.valueOf(cert.getId()), cert.getRevokedAt(), reason);
        }
        //crlBuilder.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
        //crlBuilder.addExtension(X509Extensions.CRLNumber, false, new CRLNumber(BigInteger.valueOf(1)));
        
        PrivateKeyEntry keyEntry = getSigningCertEntry();
        
        JcaContentSignerBuilder signBuilder = new JcaContentSignerBuilder(SIGNER_ALGORITHM);
        signBuilder.setProvider(BC_PROVIDER_NAME);
        ContentSigner signer;
        try {
            signer = signBuilder.build(keyEntry.getPrivateKey());
        } catch (OperatorCreationException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            return null;
        }
        
        X509CRLHolder cRLHolder = crlBuilder.build(signer);
        JcaX509CRLConverter converter = new JcaX509CRLConverter();
        converter.setProvider(BC_PROVIDER_NAME);
        X509CRL crl = null;
        try {
            crl = converter.getCRL(cRLHolder);
        } catch (CRLException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return crl;
    }

    /**
     * For some reason the X500Name is reversed when extracted from X509Certificate Principal,
     * so here we reverese it again 
     */
    private static String reverseX500Name(String name) {
        String[] RDN = name.split(",");
        StringBuffer buf = new StringBuffer(name.length());
        for(int i = RDN.length - 1; i >= 0; i--){
            if(i != RDN.length - 1)
                buf.append(',');
            buf.append(RDN[i]);
        }
        return buf.toString();
    }

    /**
     * Convert a cert/key to pem from "encoded" format (byte[])
     * 
     * @param type The type, currently "CERTIFICATE", "PUBLIC KEY", "PRIVATE KEY" or "X509 CRL" are used
     * @param encoded The encoded byte[]
     * @return The Pem formated cert/key
     */
    public static String getPemFromEncoded(String type, byte[] encoded) {
        String pemFormat = "";
        // Write certificate to PEM
        StringWriter perStrWriter = new StringWriter(); 
        PemWriter pemWrite = new PemWriter(perStrWriter);
        try {
            pemWrite.writeObject(new PemObject(type, encoded));
            pemWrite.flush();
            pemFormat = perStrWriter.toString();
            pemWrite.close();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return pemFormat;
    }
    
    public X509Certificate getCertFromString(String certificateHeader) {
        CertificateFactory certificateFactory;
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            logger.error("Exception while creating CertificateFactory", e);
            return null;
        }

        // nginx forwards the certificate in a header by replacing new lines with whitespaces
        // (2 or more). Also replace tabs, which nginx sometimes sends instead of whitespaces.
        String certificateContent = certificateHeader.replaceAll("\\s{2,}", System.lineSeparator()).replaceAll("\\t+", System.lineSeparator());
        if (certificateContent == null || certificateContent.length() < 10) {
            logger.debug("No certificate content found");
            return null;
        }
        X509Certificate userCertificate = null;
        try {
            userCertificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificateContent.getBytes("ISO-8859-11")));
        } catch (CertificateException | UnsupportedEncodingException e) {
            logger.error("Exception while converting certificate extracted from header", e);
            return null;
        }
        logger.debug("Certificate was extracted from the header");
        return userCertificate;
    }
    
    public UserDetails getUserFromCert(X509Certificate userCertificate) {
        String certDN = userCertificate.getSubjectDN().getName();
        X500Name x500name = new X500Name(certDN);
        InetOrgPerson.Essence essence = new InetOrgPerson.Essence();
        String name = getElement(x500name, BCStyle.CN);
        String uid = getElement(x500name, BCStyle.UID);
        essence.setUsername(uid);
        essence.setUid(uid);
        essence.setDn(certDN);
        essence.setCn(new String[] { name });
        essence.setSn(name);
        essence.setO(getElement(x500name, BCStyle.O));
        essence.setOu(getElement(x500name, BCStyle.OU));
        essence.setDescription(certDN);
        // Hack alert! There is no country property in this type, so we misuse PostalAddress...
        essence.setPostalAddress(getElement(x500name, BCStyle.C));
        logger.debug("Parsed certificate, name: " + name);

        // Extract info from Subject Alternative Name extension
        Collection<List<?>> san = null;
        try {
            san = userCertificate.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            logger.warn("could not extract info from Subject Alternative Names - will be ignored.");
        }
        // Check that the certificate includes the SubjectAltName extension
        if (san != null) {
            // Use the type OtherName to search for the certified server name
            Collection<GrantedAuthority> roles = new ArrayList<GrantedAuthority>();
            for (List item : san) {
                Integer type = (Integer) item.get(0);
                if (type == 0) {
                    // Type OtherName found so return the associated value
                    ASN1InputStream decoder = null;
                    String oid = "";
                    String value = "";
                    try {
                        // Value is encoded using ASN.1 so decode it to get it out again
                        decoder = new ASN1InputStream((byte[]) item.toArray()[1]);
                        DLSequence seq = (DLSequence) decoder.readObject();
                        ASN1ObjectIdentifier asnOID = (ASN1ObjectIdentifier) seq.getObjectAt(0);
                        ASN1Encodable encoded = seq.getObjectAt(1);
                        encoded = ((DERTaggedObject) encoded).getObject();
                        encoded = ((DERTaggedObject) encoded).getObject();
                        oid = asnOID.getId();
                        value = ((DERUTF8String) encoded).getString();
                    } catch (UnsupportedEncodingException e) {
                        logger.error("Error decoding subjectAltName" + e.getLocalizedMessage(),e);
                        continue;
                    } catch (Exception e) {
                        logger.error("Error decoding subjectAltName" + e.getLocalizedMessage(),e);
                        continue;
                    } finally {
                        if (decoder != null) {
                            try {
                                decoder.close();
                            } catch (IOException e) {
                            }
                        }
                    }
                    logger.debug("oid: " + oid + ", value: " + value);
                    switch (oid) {
                    case MC_OID_FLAGSTATE:
                    case MC_OID_CALLSIGN:
                    case MC_OID_IMO_NUMBER:
                    case MC_OID_MMSI_NUMBER:
                    case MC_OID_AIS_SHIPTYPE:
                    case MC_OID_PORT_OF_REGISTER:
                        logger.debug("Ship specific OIDs are ignored");
                        break;
                    case MC_OID_MRN:
                        // We only support 1 mrn
                        essence.setUid(value);
                        break;
                    case MC_OID_PERMISSIONS:
                        if (value != null && !value.trim().isEmpty()) {
                            SimpleGrantedAuthority role = new SimpleGrantedAuthority(value);
                            roles.add(role);
                        }
                        break;
                    default:
                        logger.error("Unknown OID!");
                        break;
                    }
                } else {
                    // Other types are not supported so ignore them
                    logger.warn("SubjectAltName of invalid type found: " + type);
                }
            }
            if (!roles.isEmpty()) {
                essence.setAuthorities(roles);
            }
        }
        return essence.createUserDetails();
    }

    /**
     * Returns a Maritime Cloud certificate from the truststore
     * @param alias Either ROOT_CERT_ALIAS or INTERMEDIATE_CERT_ALIAS
     * @return
     */
    private Certificate getMCCertificate(String alias) {
        logger.debug(TRUSTSTORE_PATH);
        FileInputStream is;
        try {
            is = new FileInputStream(TRUSTSTORE_PATH);
        } catch (FileNotFoundException e) {
            logger.error("Could not open truststore", e);
            return null;
        }
        KeyStore keystore;
        try {
            keystore = KeyStore.getInstance(KEYSTORE_TYPE);
            keystore.load(is, TRUSTSTORE_PASSWORD.toCharArray());
            Certificate rootCert = keystore.getCertificate(alias);
            return rootCert;
            
        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
            logger.error("Could not load root certificate", e);
            return null;
        }
    }
    
    public boolean verifyCertificate(X509Certificate certToVerify) {
        Certificate rootCert = getMCCertificate(INTERMEDIATE_CERT_ALIAS);
        JcaX509CertificateHolder certHolder;
        try {
            certHolder = new JcaX509CertificateHolder(certToVerify);
        } catch (CertificateEncodingException e) {
            logger.error("Could not create JcaX509CertificateHolder", e);
            return false;
        }
        PublicKey pubKey = rootCert.getPublicKey();
        if (pubKey == null) {
            logger.error("Could not get public key of root certificate");
            return false;
        }
        ContentVerifierProvider contentVerifierProvider = null;
        try {
            contentVerifierProvider = new JcaContentVerifierProviderBuilder().setProvider(BC_PROVIDER_NAME).build(pubKey);
        } catch (OperatorCreationException e) {
            logger.error("Could not create ContentVerifierProvider from public key", e);
            return false;
        }
        if (contentVerifierProvider == null) {
            logger.error("Created ContentVerifierProvider from root public key is null");
            return false;
        }
        try {
            if (certHolder.isSignatureValid(contentVerifierProvider)) {
                return true;
            }
        } catch (CertException e) {
            logger.error("Error when trying to validate signature", e);
            return false;
        }
        logger.debug("Certificate does not seem to be valid!");
        return false;
    }

    public BasicOCSPRespBuilder initOCSPRespBuilder(OCSPReq request) {

        SubjectPublicKeyInfo keyinfo = SubjectPublicKeyInfo.getInstance(getMCCertificate(ROOT_CERT_ALIAS).getPublicKey().getEncoded());
        BasicOCSPRespBuilder respBuilder;
        try {
            respBuilder = new BasicOCSPRespBuilder(keyinfo,
                    new JcaDigestCalculatorProviderBuilder().setProvider(BC_PROVIDER_NAME).build().get(CertificateID.HASH_SHA1)); // Create builder
        } catch (Exception e) {
            return null;
        }

        Extension ext = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (ext != null) {
            respBuilder.setResponseExtensions(new Extensions(new Extension[] { ext })); // Put the nonce back in the response
        }
        return respBuilder;
    }

    public OCSPResp generateOCSPResponse(BasicOCSPRespBuilder respBuilder) {
        PrivateKeyEntry signingCert = getSigningCertEntry();
        try {
            ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNER_ALGORITHM).setProvider(BC_PROVIDER_NAME).build(signingCert.getPrivateKey());
            BasicOCSPResp basicResp = respBuilder.build(contentSigner,
                    new X509CertificateHolder[] { new X509CertificateHolder(signingCert.getCertificate().getEncoded()) }, new Date());
            // Set response as successful
            int response = OCSPRespBuilder.SUCCESSFUL;
            // build the response
            return new OCSPRespBuilder().build(response, basicResp);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Extract a value from the DN extracted from a certificate
     * 
     * @param x500name
     * @param style
     * @return
     */
    public static String getElement(X500Name x500name, ASN1ObjectIdentifier style) {
        try {
            RDN cn = x500name.getRDNs(style)[0];
            return valueToString(cn.getFirst().getValue());
        } catch (ArrayIndexOutOfBoundsException e) {
            return null;
        }
    }

    /**
     * Simplified version of IETFUtils.valueToString where some "special" chars was escaped
     * @param value
     * @return
     */
    public static String valueToString(ASN1Encodable value)
    {
        StringBuffer vBuf = new StringBuffer();
        if (value instanceof ASN1String && !(value instanceof DERUniversalString)) {
            String v = ((ASN1String)value).getString();
            vBuf.append(v);
        } else {
            try {
                vBuf.append("#" + bytesToString(Hex.encode(value.toASN1Primitive().getEncoded(ASN1Encoding.DER))));
            } catch (IOException e) {
                throw new IllegalArgumentException("Other value has no encoded form");
            }
        }
        logger.debug(vBuf.toString());
        return vBuf.toString();
    }
    
    private static String bytesToString(byte[] data) {
        char[]  cs = new char[data.length];
        for (int i = 0; i != cs.length; i++) {
            cs[i] = (char)(data[i] & 0xff);
        }
        return new String(cs);
    }

    /* 
     * Uncomment this, build, and run class with ./setup/initca.sh to init CA certificates.
     * You might want to edit CERT_EXPIRE_YEAR to make sure the root cert is valid longer that the certificates it signs.
     * You might also want to change rootCertX500Name, mcidregCertX500Name, ocspUrl and crlUrl to reflect your setup,
     * remember to put mcidregCertX500Name in application.yaml at net.maritimecloud.idreg.certs.mcidreg-cert-x500-name.
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("Initializing CA");
        String ocspUrl = "https://localhost/x509/api/certificates/ocsp";
        String crlUrl = "https://localhost/x509/api/certificates/crl";
        CertificateUtil certUtil = new CertificateUtil();
        String rootCertX500Name = "C=DK, ST=Denmark, L=Copenhagen, O=MaritimeCloud Test, OU=MaritimeCloud Test, CN=MaritimeCloud Test Root Certificate, E=info@maritimecloud.net";
        System.out.println("Root CA DN: " + rootCertX500Name);
        String mcidregCertX500Name = "C=DK, ST=Denmark, L=Copenhagen, O=MaritimeCloud Test, OU=MaritimeCloud Test Identity Registry, CN=MaritimeCloud Test Identity Registry Certificate, E=info@maritimecloud.net";
        System.out.println("MC Id Reg intermediate cert DN: " + mcidregCertX500Name);
        certUtil.initCA(rootCertX500Name, mcidregCertX500Name, crlUrl, ocspUrl);
        System.out.println("Done initializing CA");
    }*/
}
