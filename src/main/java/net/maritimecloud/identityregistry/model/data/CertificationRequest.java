/*
 * Copyright 2018 Danish Maritime Authority
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.maritimecloud.identityregistry.model.data;

import io.swagger.annotations.ApiModelProperty;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import net.maritimecloud.identityregistry.model.JsonSerializable;

@Getter
@Setter
@ToString
public class CertificationRequest implements JsonSerializable {

    /**
     * A BASE64 encoded BER/DER encoded PKCS#10 certificate signing request
     */
    @ApiModelProperty(required = true, value = "The BASE64 encoded BER/DER encoded PKCS#10 certificate signing request that is to be signed by the CA")
    private String pkcs10Csr;
}
