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
package net.maritimeconnectivity.identityregistry.model.data;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import net.maritimeconnectivity.identityregistry.model.JsonSerializable;

import static io.swagger.v3.oas.annotations.media.Schema.AccessMode.READ_ONLY;

/**
 * Object that bundles a PEM certificate with keystores in JKS and PKCS12 format and a password for the keystores
 *
 * @deprecated only used when issuing certificates with server generated keys. Will be removed in the future
 */
@AllArgsConstructor
@Getter
@Deprecated
@Schema(description = "Represents a bundle containing an PEM encoded certificate, keystores in JKS and PKCS#12 format " +
        "and a password for the keystores. Will be removed in the future", deprecated = true)
public class CertificateBundle implements JsonSerializable {
    @Schema(description = "The PEM encoded certificate", accessMode = READ_ONLY)
    private PemCertificate pemCertificate;
    @Schema(description = "JKS keystore containing certificate and private key", accessMode = READ_ONLY)
    private String jksKeystore;
    @Schema(description = "PKCS#12 keystore containing certificate and private key", accessMode = READ_ONLY)
    private String pkcs12Keystore;
    @Schema(description = "The password for the keystores", accessMode = READ_ONLY)
    private String keystorePassword;
}
