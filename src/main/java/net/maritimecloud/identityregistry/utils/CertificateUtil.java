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
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableEntryException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
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
    // Generate more random OIDs at http://www.itu.int/en/ITU-T/asn1/Pages/UUID/generate_uuid.aspx
    public static final String FLAGSTATE_OID = "2.25.323100633285601570573910217875371967771";


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
        /*X509v1CertificateBuilder certBldr = new JcaX509v1CertificateBuilder(new X500Name(issuer),
                                                                            BigInteger.valueOf(1),
                                                                            new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000),
                                                                            new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000),
                                                                            new X500Name(subject),
                                                                            subjectPublicKey);*/
        X509v3CertificateBuilder certV3Bldr = new JcaX509v3CertificateBuilder(new X500Name(issuer),
                                                                                BigInteger.valueOf(serialNumber),
                                                                                new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000),
                                                                                new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000),
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
            Vector<Attribute> attributeVector = new Vector<Attribute>();
            Attribute atribute = new Attribute(new ASN1ObjectIdentifier(FLAGSTATE_OID), new DERSet(new DERPrintableString("")));
            attributeVector.add(atribute);
            SubjectDirectoryAttributes sda = new SubjectDirectoryAttributes(attributeVector);
            certV3Bldr = certV3Bldr.addExtension(Extension.authorityKeyIdentifier, false, extensionUtil.createAuthorityKeyIdentifier(signerPublicKey))
                                   .addExtension(Extension.subjectKeyIdentifier, false, extensionUtil.createSubjectKeyIdentifier(subjectPublicKey))
                                   .addExtension(Extension.subjectDirectoryAttributes, false, sda);

        }
        JcaContentSignerBuilder builder = new JcaContentSignerBuilder(SIGNER_ALGORITHM);
        builder.setProvider(BC_PROVIDER_NAME);
        ContentSigner signer = builder.build(signerPrivateKey);
        return new JcaX509CertificateConverter().setProvider(BC_PROVIDER_NAME).getCertificate(certV3Bldr.build(signer));
    }
    
    
    /*public static void generateCert(KeyPair kp) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        
        builder.addRDN(BCStyle.C, "DK");
        builder.addRDN(BCStyle.O, "MaritimeCloud");
        builder.addRDN(BCStyle.OU, "MaritimeCloud Identity Registry");
        builder.addRDN(BCStyle.CN, "MaritimeCloud Identity Registry Root Certificate");
        builder.addRDN(BCStyle.E, "info@maritimecloud.net");

        // create the certificate - version 3 - without extensions
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA224withECDSA");
        //AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

        //ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(kp.getPrivate());
        //AlgorithmIdentifier pubAlgId = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE));
        //SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(pubAlgId, (ASN1Encodable) new RSAPublicKey(lwPubKey.getModulus(), lwPubKey.getExponent());
        SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(kp.getPublic().getEncoded()));
        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(builder.build(), 
                                                                        BigInteger.valueOf(1), 
                                                                        new Date(System.currentTimeMillis() - 50000),
                                                                        new Date(System.currentTimeMillis() + 50000), 
                                                                        builder.build(), 
                                                                        pubInfo);

        X509CertificateHolder certHolder = certGen.build(sigGen);
        System.out.println(certHolder.getEncoded().toString());
    }*/
    
    
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
        FileInputStream fis = null;
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
     * Loads the root MaritimeCloud certificate from the keystore
     *  
     * @return
     */
    public static PrivateKeyEntry getRootCertEntry() {
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
            PrivateKeyEntry rootCertEntry = (PrivateKeyEntry) keystore.getEntry(INTERMEDIATE_CERT_ALIAS, protParam);
            return rootCertEntry;
            
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
    public static X509Certificate generateCertForEntity(Long serialNumber, String country, String orgName, String orgUnitName, String callName, String email, PublicKey publickey) {
        PrivateKeyEntry rootCertEntry = CertificateUtil.getRootCertEntry();
        java.security.cert.Certificate rootCert = rootCertEntry.getCertificate();
        X509Certificate rootx509cert = (X509Certificate) rootCert;
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
        HashMap<String, String> customAttr = new HashMap<String, String>();
        customAttr.put(FLAGSTATE_OID, orgCountryCode);
        X509Certificate orgCert = null;
        try {
            orgCert = CertificateUtil.buildAndSignCert(serialNumber, rootCertEntry.getPrivateKey(), rootx509cert.getPublicKey(), publickey, MCIDREG_CERT_X500_NAME, orgSubjectDn, customAttr, "ENTITY");
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
            crlBuilder.addCRLEntry(BigInteger.valueOf(cert.getId().longValue()), now, reason);
        }
        //crlBuilder.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
        //crlBuilder.addExtension(X509Extensions.CRLNumber, false, new CRLNumber(BigInteger.valueOf(1)));
        
        PrivateKeyEntry keyEntry = getRootCertEntry();
        
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
