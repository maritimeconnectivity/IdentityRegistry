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

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import net.maritimecloud.pki.CertificateBuilder;
import net.maritimecloud.pki.KeystoreHandler;
import net.maritimecloud.pki.PKIConfiguration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

@Component
@Slf4j
public class CertificateUtil {

    // Values below are loaded from application.test
    @Value("${net.maritimecloud.idreg.certs.sub-ca-keystore-path}")
    private String subCaKeystorePath;

    @Value("${net.maritimecloud.idreg.certs.sub-ca-keystore-password}")
    private String subCaKeystorePassword;

    @Value("${net.maritimecloud.idreg.certs.sub-ca-key-password}")
    private String subCaKeyPassword;

    @Value("${net.maritimecloud.idreg.certs.truststore-path}")
    private String truststorePath;

    @Value("${net.maritimecloud.idreg.certs.truststore-password}")
    private String truststorePassword;

    @Getter
    @Value("${net.maritimecloud.idreg.certs.root-crl-path}")
    private String rootCrlPath;

    @Getter
    @Value("${net.maritimecloud.idreg.certs.base-crl-ocsp-path}")
    private String baseCrlOcspCrlURI;

    @Getter
    @Value("${net.maritimecloud.idreg.certs.default-sub-ca}")
    private String defaultSubCa;

    @Getter
    @Value("${net.maritimecloud.idreg.certs.root-ca-alias")
    private String rootCAAlias;

    @Getter
    private KeystoreHandler keystoreHandler;

    @Getter
    private CertificateBuilder certificateBuilder;

    private PKIConfiguration pkiConfiguration;

    public CertificateUtil() {
    }

    @PostConstruct
    public void setup() {
        pkiConfiguration = new PKIConfiguration(rootCAAlias);
        pkiConfiguration.setTruststorePath(truststorePath);
        pkiConfiguration.setTruststorePassword(truststorePassword);
        pkiConfiguration.setSubCaKeystorePath(subCaKeystorePath);
        pkiConfiguration.setSubCaKeystorePassword(subCaKeystorePassword);
        pkiConfiguration.setSubCaKeyPassword(subCaKeyPassword);

        keystoreHandler = new KeystoreHandler(pkiConfiguration);
        certificateBuilder = new CertificateBuilder(keystoreHandler);
    }

}
