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
import java.security.KeyStore.Entry;
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
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Locale;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author tgc
 *
 */
public class CertificateUtil {

    public static final String ROOT_CERT_X500_NAME = "C=DK, ST=Denmark, L=Copenhagen, O=MaritimeCloud, OU=MaritimeCloud Identity Registry, CN=MaritimeCloud Identity Registry Root Certificate, E=info@maritimecloud.net";
    public static final String KEYSTORE_PATH = "/tmp/mc-keystore.jks";
    public static final String KEYSTORE_PASSWORD = "changeit";
    public static final String ROOT_CERT_ALIAS = "rootcert";
    public static final String BC_PROVIDER_NAME = "BC";
    
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
    public static X509Certificate buildAndSignCert(PrivateKey signerPrivateKey, PublicKey subjectPublicKey, String issuer, String subject) throws Exception {
        X509v1CertificateBuilder certBldr = new JcaX509v1CertificateBuilder(new X500Name(issuer),
                                                                            BigInteger.valueOf(1),
                                                                            new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000),
                                                                            new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000),
                                                                            new X500Name(subject),
                                                                            subjectPublicKey);
        JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA224withECDSA");
        builder.setProvider(CertificateUtil.BC_PROVIDER_NAME);
        ContentSigner signer = builder.build(signerPrivateKey);
        return new JcaX509CertificateConverter().setProvider(CertificateUtil.BC_PROVIDER_NAME).getCertificate(certBldr.build(signer));
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
     * 
     * @param kp
     * @param keystoreFilename
     * @param password
     */
    public static void saveKeyPairInKeyStore(KeyPair kp, String keystoreFilename, String password) {
        KeyStore ks;
        FileOutputStream fos = null;
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, password.toCharArray());
            // Store away the keystore.
            fos = new FileOutputStream(keystoreFilename);
            X509Certificate cert;
            try {
                cert = CertificateUtil.buildAndSignCert(kp.getPrivate(), kp.getPublic(), CertificateUtil.ROOT_CERT_X500_NAME, CertificateUtil.ROOT_CERT_X500_NAME);
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                return;
            }
            Certificate[] certChain = new Certificate[1];  
            certChain[0] = cert;
            ks.setKeyEntry(CertificateUtil.ROOT_CERT_ALIAS, kp.getPrivate(), password.toCharArray(), certChain);
            ks.store(fos, password.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return;
        } finally {
            try {
                if (fos != null) {
                    fos.close();
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
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("prime192v1");
        KeyPairGenerator g;
        try {
            g = KeyPairGenerator.getInstance("ECDSA", CertificateUtil.BC_PROVIDER_NAME);
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
            is = new FileInputStream(CertificateUtil.KEYSTORE_PATH);
        } catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
        KeyStore keystore;
        try {
            keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(is, CertificateUtil.KEYSTORE_PASSWORD.toCharArray());
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(CertificateUtil.KEYSTORE_PASSWORD.toCharArray());
            PrivateKeyEntry rootCertEntry = (PrivateKeyEntry) keystore.getEntry(CertificateUtil.ROOT_CERT_ALIAS, protParam);
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
    public static X509Certificate generateCertForEntity(String country, String orgName, String orgUnitName, String callName, String email, PublicKey publickey) {
        PrivateKeyEntry rootCertEntry = CertificateUtil.getRootCertEntry();
        java.security.cert.Certificate rootCert = rootCertEntry.getCertificate();
        X509Certificate rootx509cert = (X509Certificate) rootCert;
        // Get subject
        Principal principal = rootx509cert.getSubjectDN();
        String rootSubjectDn = principal.getName();
        // Get issuer
        //principal = rootx509cert.getIssuerDN();
        //String issuerDn = principal.getName();
        
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
            orgCert = CertificateUtil.buildAndSignCert(rootCertEntry.getPrivateKey(), publickey, rootSubjectDn, orgSubjectDn);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return orgCert;

    }
    
    /**
     * Convert a cert/key to pem from "encoded" format (byte[])
     * 
     * @param type The type, currently "CERTIFICATE", "PUBLIC KEY" or "PRIVATE KEY" are used
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

}
