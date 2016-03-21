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
package net.maritimecloud.identityregistry.utils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CertificateUtil {

    public static final String ROOT_CERT_X500_NAME = "C=DK, ST=Denmark, L=Copenhagen, O=MaritimeCloud, OU=MaritimeCloud, CN=MaritimeCloud Root Certificate, E=info@maritimecloud.net";
    public static final String MCIDREG_CERT_X500_NAME = "C=DK, ST=Denmark, L=Copenhagen, O=MaritimeCloud, OU=MaritimeCloud Identity Registry, CN=MaritimeCloud Identity Registry Certificate, E=info@maritimecloud.net";
    public static final String ROOT_KEYSTORE_PATH = "mc-root-keystore.jks"; // /etc/ssl/certs/java/cacerts
    public static final String INTERMEDIATE_KEYSTORE_PATH = "mc-it-keystore.jks";
    public static final String KEYSTORE_PASSWORD = "changeit";
    public static final String TRUSTSTORE_PATH = "mc-truststore.jks";
    public static final String TRUSTSTORE_PASSWORD = "changeit";
    public static final String ROOT_CERT_ALIAS = "rootcert";
    public static final String INTERMEDIATE_CERT_ALIAS = "imcert";
    public static final String BC_PROVIDER_NAME = "BC";
    public static final String KEYSTORE_TYPE = "jks";
    public static final String SIGNER_ALGORITHM = "SHA224withECDSA";

    // OIDs used for the extra info stored in the SubjectAlternativeName extension
    // Generate more random OIDs at http://www.itu.int/en/ITU-T/asn1/Pages/UUID/generate_uuid.aspx
    public static final String MC_OID_FLAGSTATE = "2.25.323100633285601570573910217875371967771";
    public static final String MC_OID_CALLSIGN = "2.25.208070283325144527098121348946972755227";
    public static final String MC_OID_IMO_NUMBER = "2.25.291283622413876360871493815653100799259";
    public static final String MC_OID_MMSI_NUMBER = "2.25.328433707816814908768060331477217690907";
    // See http://www.shipais.com/doc/Pifaq/1/22/ and https://help.marinetraffic.com/hc/en-us/articles/205579997-What-is-the-significance-of-the-AIS-SHIPTYPE-number-
    public static final String MC_OID_AIS_SHIPTYPE = "2.25.107857171638679641902842130101018412315";
    public static final String MC_OID_MRN = "2.25.57343886297412775677905049923597223195";
    public static final String MC_OID_PERMISSIONS = "2.25.174437629172304915481663724171734402331";

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
    public static X509Certificate buildAndSignCert(Long serialNumber, PrivateKey signerPrivateKey, PublicKey signerPublicKey, PublicKey subjectPublicKey, String issuer, String subject,
                                                   Map<String, String> customAttrs, String type) throws Exception {
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DATE, -1);
        Date yesterday = cal.getTime();
        cal.add(Calendar.DATE, 1);
        cal.add(Calendar.YEAR, 1);
        Date nextYear = cal.getTime();
        X509v3CertificateBuilder certV3Bldr = new JcaX509v3CertificateBuilder(new X500Name(issuer),
                                                                                BigInteger.valueOf(serialNumber),
                                                                                yesterday, // Valid from yesterday 
                                                                                nextYear, // Valid for a year
                                                                                new X500Name(subject),
                                                                                subjectPublicKey);
        JcaX509ExtensionUtils extensionUtil = new JcaX509ExtensionUtils();
        // Create certificate extensions
        if ("ROOTCA".equals(type)) {
            certV3Bldr = certV3Bldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                                   .addExtension(Extension.keyUsage, true, new X509KeyUsage(X509KeyUsage.digitalSignature |
                                                                                            X509KeyUsage.nonRepudiation   |
                                                                                            X509KeyUsage.keyEncipherment  |
                                                                                            X509KeyUsage.keyCertSign      |
                                                                                            X509KeyUsage.dataEncipherment));
        } else if ("INTERMEDIATE".equals(type)) {
            certV3Bldr = certV3Bldr.addExtension(Extension.keyUsage, true, new X509KeyUsage(X509KeyUsage.digitalSignature |
                                                                                            X509KeyUsage.nonRepudiation   |
                                                                                            X509KeyUsage.keyEncipherment  |
                                                                                            X509KeyUsage.keyCertSign      |
                                                                                            X509KeyUsage.dataEncipherment))
                                   .addExtension(Extension.authorityKeyIdentifier, false, extensionUtil.createAuthorityKeyIdentifier(signerPublicKey))
                                   .addExtension(Extension.subjectKeyIdentifier, false, extensionUtil.createSubjectKeyIdentifier(subjectPublicKey));
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
            certV3Bldr = certV3Bldr.addExtension(Extension.authorityKeyIdentifier, false, extensionUtil.createAuthorityKeyIdentifier(signerPublicKey))
                                   .addExtension(Extension.subjectKeyIdentifier, false, extensionUtil.createSubjectKeyIdentifier(subjectPublicKey));
            if (genNames != null) {
                certV3Bldr = certV3Bldr.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(genNames));
            }
        }
        JcaContentSignerBuilder builder = new JcaContentSignerBuilder(SIGNER_ALGORITHM);
        builder.setProvider(BC_PROVIDER_NAME);
        ContentSigner signer = builder.build(signerPrivateKey);
        return new JcaX509CertificateConverter().setProvider(BC_PROVIDER_NAME).getCertificate(certV3Bldr.build(signer));
    }
    
    /**
     * Generates a self-signed certificate based on the keypair and saves it in the keystore.
     * Should only be used to init the CA.
     * 
     * @param keystoreFilename
     * @param password
     */
    public static void initCA() {
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
                cacert = CertificateUtil.buildAndSignCert(Long.valueOf(0), cakp.getPrivate(), cakp.getPublic(), cakp.getPublic(),
                                                        ROOT_CERT_X500_NAME, ROOT_CERT_X500_NAME, null, "ROOTCA");
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                return;
            }
            X509Certificate imcert;
            try {
                imcert = CertificateUtil.buildAndSignCert(Long.valueOf(0), cakp.getPrivate(), cakp.getPublic(), imkp.getPublic(),
                                                        ROOT_CERT_X500_NAME, MCIDREG_CERT_X500_NAME, null, "INTERMEDIATE");
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
    public static PrivateKeyEntry getSigningCertEntry() {
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
     * @param orgUnitName The name of the organizational unit the entity belongs to
     * @param callName The name of the entity
     * @param email The email of the entity
     * @param publickey The public key of the entity
     * @return Returns a signed X509Certificate
     */
    public static X509Certificate generateCertForEntity(Long serialNumber, String country, String orgName, String orgUnitName, String callName, String email, PublicKey publickey, Map<String, String> customAttr) {
        PrivateKeyEntry signingCertEntry = CertificateUtil.getSigningCertEntry();
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
                              "OU=" + orgUnitName + ", " +
                              "CN=" + callName + ", " +
                              "E=" + email;
        X509Certificate orgCert = null;
        try {
            orgCert = CertificateUtil.buildAndSignCert(serialNumber, signingCertEntry.getPrivateKey(), signingX509Cert.getPublicKey(), publickey, MCIDREG_CERT_X500_NAME, orgSubjectDn, customAttr, "ENTITY");
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return orgCert;
    }
    
    /**
     * Creates a Certificate Revocation List (CRL) for the certificate serialnumbers given.
     * 
     * @param revokesSerialNumbers  List of the serialnumbers that should be revoked.
     * @return
     */
    public static X509CRL generateCRL(List<net.maritimecloud.identityregistry.model.Certificate> revokedCerts) {
        Date now = new Date();
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(new X500Name(MCIDREG_CERT_X500_NAME), now);
        crlBuilder.setNextUpdate(new Date(now.getTime() + 100000));
        for (net.maritimecloud.identityregistry.model.Certificate cert : revokedCerts) {
            int reason = 0;
            String certReason = cert.getRevokeReason().toLowerCase();
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
            crlBuilder.addCRLEntry(BigInteger.valueOf(cert.getId()), now, reason);
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
    
    /* 
     * Uncomment this, build, and run class with ./setup/initca.sh to init CA certificates
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("Initializing CA");
        CertificateUtil.initCA();
        System.out.println("Done initializing CA");
    }*/
}
