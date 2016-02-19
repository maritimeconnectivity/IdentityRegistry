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
package net.maritimecloud.identityregistry.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

public class CertificateRevocation implements JsonSerializable {

    private Date revokedAt;

    private String revokationReason;

    public boolean validateReason() {
        ArrayList<String> validReasons = new ArrayList<String>(Arrays.asList(
            "unspecified",
            "keycompromise",
            "cacompromise",
            "affiliationchanged",
            "superseded",
            "cessationofoperation",
            "certificatehold",
            "removefromcrl",
            "privilegewithdrawn",
            "aaCompromise"));
        String reason = getRevokationReason();
        if (reason != null && validReasons.contains(reason)) {
            return true;
        }
        return false;
    }

    public Date getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(Date revokedAt) {
        this.revokedAt = revokedAt;
    }

    public String getRevokationReason() {
        return revokationReason;
    }

    public void setRevokationReason(String revokationReason) {
        if (revokationReason != null) {
            revokationReason = revokationReason.toLowerCase();
        }
        this.revokationReason = revokationReason;
    }


}
