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
package net.maritimeconnectivity.identityregistry.model.data;

import com.fasterxml.jackson.annotation.JsonAlias;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import net.maritimeconnectivity.identityregistry.model.JsonSerializable;
import net.maritimeconnectivity.identityregistry.validators.InPredefinedList;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.Date;
import java.util.List;

@Getter
@Setter
@ToString
@Schema(description = "Model object representing a certificate revocation")
public class CertificateRevocation implements JsonSerializable {

    private static final List<String> VALID_REVOCATION_REASONS = List.of("unspecified", "keycompromise", "cacompromise",
            "affiliationchanged", "superseded", "cessationofoperation", "certificatehold", "removefromcrl",
            "privilegewithdrawn", "aacompromise");

    @Schema(description = "The date the certificate revocation should be activated.", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotNull
    private Date revokedAt;

    @Schema(
            requiredMode = Schema.RequiredMode.REQUIRED,
            description = "The reason the certificates has been revoked",
            allowableValues = {"unspecified", "keycompromise", "cacompromise", "affiliationchanged", "superseded",
                    "cessationofoperation", "certificatehold", "removefromcrl", "privilegewithdrawn", "aacompromise"}
    )
    @InPredefinedList(
            acceptedValues = {"unspecified", "keycompromise", "cacompromise", "affiliationchanged", "superseded",
                    "cessationofoperation", "certificatehold", "removefromcrl", "privilegewithdrawn", "aacompromise"}
    )
    @NotBlank
    @JsonAlias({"revokationReason"})
    private String revocationReason;

    public boolean validateReason() {
        return (revocationReason != null && VALID_REVOCATION_REASONS.contains(revocationReason));
    }

    public void setRevocationReason(String revocationReason) {
        if (revocationReason != null) {
            revocationReason = revocationReason.toLowerCase();
        }
        this.revocationReason = revocationReason;
    }


}
