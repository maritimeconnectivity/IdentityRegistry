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
package net.maritimeconnectivity.identityregistry.utils;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.pki.CertificateBuilder;
import net.maritimeconnectivity.pki.KeystoreHandler;
import net.maritimeconnectivity.pki.PKIConfiguration;
import net.maritimeconnectivity.pki.pkcs11.P11PKIConfiguration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;

@Component
@Slf4j
@NoArgsConstructor
public class CertificateUtil {

    // Values below are loaded from application.test
    @Value("${net.maritimeconnectivity.idreg.certs.sub-ca-keystore-path}")
    private String subCaKeystorePath;

    @Value("${net.maritimeconnectivity.idreg.certs.sub-ca-keystore-password}")
    private String subCaKeystorePassword;

    @Value("${net.maritimeconnectivity.idreg.certs.sub-ca-key-password}")
    private String subCaKeyPassword;

    @Value("${net.maritimeconnectivity.idreg.certs.truststore-path}")
    private String truststorePath;

    @Value("${net.maritimeconnectivity.idreg.certs.truststore-password}")
    private String truststorePassword;

    @Getter
    @Value("${net.maritimeconnectivity.idreg.certs.root-crl-path}")
    private String rootCrlPath;

    @Getter
    @Value("${net.maritimeconnectivity.idreg.certs.base-crl-ocsp-path}")
    private String baseCrlOcspCrlURI;

    @Getter
    @Value("${net.maritimeconnectivity.idreg.certs.default-sub-ca}")
    private String defaultSubCa;

    @Getter
    @Value("${net.maritimeconnectivity.idreg.certs.root-ca-alias}")
    private String rootCAAlias;

    @Getter
    @Value("${net.maritimeconnectivity.idreg.certs.pkcs11.enabled:false}")
    private boolean isUsingPKCS11;

    @Value("${net.maritimeconnectivity.idreg.certs.pkcs11.config.file:pkcs11.cfg}")
    private String pkcs11ConfigFile;

    @Value("${net.maritimeconnectivity.idreg.certs.pkcs11.config.pin:1234}")
    private String pkcs11Pin;

    @Getter
    private KeystoreHandler keystoreHandler;

    @Getter
    private CertificateBuilder certificateBuilder;

    @Getter
    private PKIConfiguration pkiConfiguration;

    @Value("${net.maritimeconnectivity.idreg.certs.validity-period.user:6}")
    private int validityPeriodForUser;

    @Value("${net.maritimeconnectivity.idreg.certs.validity-period.organization:6}")
    private int validityPeriodForOrg;

    @Value("${net.maritimeconnectivity.idreg.certs.validity-period.device:6}")
    private int validityPeriodForDevice;

    @Value("${net.maritimeconnectivity.idreg.certs.validity-period.vessel:6}")
    private int validityPeriodForVessel;

    @Value("${net.maritimeconnectivity.idreg.certs.validity-period.service:6}")
    private int validityPeriodForService;

    @Value("${net.maritimeconnectivity.idreg.certs.validity-period.mms:6}")
    private int validityPeriodForMms;

    @PostConstruct
    public void setup() {
        if (isUsingPKCS11) {
            pkiConfiguration = new P11PKIConfiguration(rootCAAlias, pkcs11ConfigFile, pkcs11Pin);
            pkiConfiguration.setTruststorePath(truststorePath);
            pkiConfiguration.setTruststorePassword(truststorePassword);
        } else {
            pkiConfiguration = new PKIConfiguration(rootCAAlias);
            pkiConfiguration.setTruststorePath(truststorePath);
            pkiConfiguration.setTruststorePassword(truststorePassword);
            pkiConfiguration.setSubCaKeystorePath(subCaKeystorePath);
            pkiConfiguration.setSubCaKeystorePassword(subCaKeystorePassword);
            pkiConfiguration.setSubCaKeyPassword(subCaKeyPassword);
        }
        keystoreHandler = new KeystoreHandler(pkiConfiguration);
        certificateBuilder = new CertificateBuilder(keystoreHandler);
    }

    public int getValidityPeriod(String type) {
        return switch (type) {
            case "user" -> validityPeriodForUser;
            case "organization" -> validityPeriodForOrg;
            case "device" -> validityPeriodForDevice;
            case "service" -> validityPeriodForService;
            case "vessel" -> validityPeriodForVessel;
            case "mms" -> validityPeriodForMms;
            default -> -1;
        };
    }
}
