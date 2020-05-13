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
package net.maritimeconnectivity.identityregistry.utils;

import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Utility class to validate and extract certain info from MRNs
 */
@Component
public class MrnUtil {

    public final Pattern mrnPattern = Pattern.compile("^urn:mrn:([a-z0-9]([a-z0-9]|-){0,20}[a-z0-9]):([a-z0-9][-a-z0-9]{0,20}[a-z0-9]):((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)|/)*)((\\?\\+((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)|/|\\?)*))?(\\?=((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)|/|\\?)*))?)?(#(((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)|/|\\?)*))?$", Pattern.CASE_INSENSITIVE);
    public final Pattern mcpMrnPattern = Pattern.compile("^urn:mrn:mcp:(device|org|user|vessel|service|mms):([a-z0-9]([a-z0-9]|-){0,20}[a-z0-9]):((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)|/)*)$", Pattern.CASE_INSENSITIVE);

    @Getter
    @Setter
    @Value("${net.maritimeconnectivity.idreg.ip-id}")
    private String ipId;

    public String getOrgShortNameFromOrgMrn(String orgMrn) {
        String[] mrnSplit = orgMrn.split(":");
        if (!mcpMrnPattern.matcher(orgMrn).matches()) {
            throw new IllegalArgumentException(MCIdRegConstants.MRN_IS_NOT_VALID);
        }
        return mrnSplit[mrnSplit.length - 1];
    }

    public String getOrgShortNameFromEntityMrn(String entityMrn) {
        String[] mrnSplit = entityMrn.split(":");
        if (!mcpMrnPattern.matcher(entityMrn).matches() || mrnSplit.length < 7) {
            throw new IllegalArgumentException(MCIdRegConstants.MRN_IS_NOT_VALID);
        }
        return mrnSplit[5];
    }

    public String getEntityIdFromMrn(String entityMrn) {
        String[] mrnSplit = entityMrn.split(":");
        if (mrnSplit.length < 7) {
            throw new IllegalArgumentException(MCIdRegConstants.MRN_IS_NOT_VALID);
        }
        if (mrnSplit.length > 7) {
            List<String> idList = new ArrayList<>(Arrays.asList(mrnSplit).subList(6, mrnSplit.length));
            return String.join(":", idList);
        }
        return mrnSplit[mrnSplit.length - 1];
    }

    public boolean isNotMrnEmpty(String mrn) {
        return (mrn != null) && !(mrn.trim().isEmpty());
    }

    public boolean validateMrn(String mrn) {
        return isNotMrnEmpty(mrn) && mrnPattern.matcher(mrn).matches();
    }

    public boolean validateMCPMrn(String mrn) {
        if(validateMrn(mrn) && mcpMrnPattern.matcher(mrn).matches()){
            String[] parts = mrn.split(":");
            if (parts.length < 6) {
                throw new IllegalArgumentException(MCIdRegConstants.MRN_IS_NOT_VALID);
            }
            if (!parts[4].equals(ipId)) {
                throw new IllegalArgumentException("MCP MRN does not contain the correct identity provider ID");
            }
            switch (parts[3]) {
                case "user":
                case "device":
                case "vessel":
                case "mms":
                    if (parts.length < 7) {
                        throw new IllegalArgumentException(MCIdRegConstants.MRN_IS_NOT_VALID);
                    }
                    break;
                case "service":
                    if (parts.length < 8 || !parts[6].equals("instance")) {
                        throw new IllegalArgumentException("The given MRN is not a valid service instance MRN");
                    }
                    break;
                default:
                    break;
            }
            return true;
        }
        return false;
    }

    /**
     * Get MRN prefix. Would be 'urn:mrn:mcl' for 'urn:mrn:mcl:org:dma', and 'urn:mrn:stm' for 'urn:mrn:stm:user:sma:user42'
     * @param mrn
     * @return
     */
    public String getMrnPrefix(String mrn) {
        // mrn always starts with 'urn:mrn:<sub-namespace>'
        int prefixEnd = mrn.indexOf(':', 8);
        return mrn.substring(0, prefixEnd);
    }

}
