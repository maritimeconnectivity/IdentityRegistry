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
package net.maritimecloud.identityregistry.model.data;

import io.swagger.annotations.ApiModelProperty;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import net.maritimecloud.identityregistry.model.JsonSerializable;
import net.maritimecloud.identityregistry.validators.InPredefinedList;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
@Getter
@Setter
@ToString
public class CertificateRevocation implements JsonSerializable {

    @ApiModelProperty(value = "The date the certificate revocation should be activated.", required = true)
    @NotNull
    private Date revokedAt;

    @ApiModelProperty(
            required = true,
            value = "The reason the certificates has been revoked",
            allowableValues = "unspecified, keycompromise, cacompromise, affiliationchanged, superseded, cessationofoperation, certificatehold, removefromcrl, privilegewithdrawn, aacompromise"
    )
    @InPredefinedList(
            acceptedValues = {"unspecified", "keycompromise", "cacompromise", "affiliationchanged", "superseded",
                    "cessationofoperation", "certificatehold", "removefromcrl", "privilegewithdrawn", "aacompromise"}
    )
    @NotBlank
    private String revokationReason;

    public boolean validateReason() {
        ArrayList<String> validReasons = new ArrayList<>(Arrays.asList(
                "unspecified",
                "keycompromise",
                "cacompromise",
                "affiliationchanged",
                "superseded",
                "cessationofoperation",
                "certificatehold",
                "removefromcrl",
                "privilegewithdrawn",
                "aacompromise"));
        String reason = getRevokationReason();
        if (reason != null && validReasons.contains(reason)) {
            return true;
        }
        return false;
    }

    public void setRevokationReason(String revokationReason) {
        if (revokationReason != null) {
            revokationReason = revokationReason.toLowerCase();
        }
        this.revokationReason = revokationReason;
    }


}
