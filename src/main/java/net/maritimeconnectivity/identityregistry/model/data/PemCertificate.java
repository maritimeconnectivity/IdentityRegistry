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
import lombok.Setter;
import lombok.ToString;
import net.maritimeconnectivity.identityregistry.model.JsonSerializable;

import static io.swagger.v3.oas.annotations.media.Schema.AccessMode.READ_ONLY;

@AllArgsConstructor
@Getter
@Setter
@ToString
@Deprecated
@Schema(description = "Model object representing an PEM encoded certificate", deprecated = true)
public class PemCertificate implements JsonSerializable {
    @Schema(description = "The private key of the certificate", accessMode = READ_ONLY)
    private String privateKey;
    @Schema(description = "The public key of the certificate", accessMode = READ_ONLY)
    private String publicKey;
    @Schema(description = "The certificate", accessMode = READ_ONLY)
    private String certificate;
}
