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

import org.springframework.beans.factory.annotation.Value;

import java.util.regex.Pattern;

/**
 * Utility class to validate and extract certain info from MRNs
 */
public class MrnUtil {

    private static String ipId;

    public static final Pattern MRN_PATTERN = Pattern.compile("^urn:mrn:([a-z0-9]([a-z0-9]|-){0,20}[a-z0-9]):([a-z0-9][-a-z0-9]{0,20}[a-z0-9]):((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)|/)*)((\\?\\+((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)|/|\\?)*))?(\\?=((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)|/|\\?)*))?)?(#(((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)|/|\\?)*))?$", Pattern.CASE_INSENSITIVE);
    public static final Pattern MCP_MRN_PATTERN = Pattern.compile("^urn:mrn:mcp:(device|org|user|vessel|service|mms):([a-z0-9]([a-z0-9]|-){0,20}[a-z0-9]):((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)((([-._a-z0-9]|~)|%[0-9a-f][0-9a-f]|([!$&'()*+,;=])|:|@)|/)*)$", Pattern.CASE_INSENSITIVE);

    private MrnUtil() {
    }

    @Value("${net.maritimeconnectivity.idreg.ip-id}")
    public void setIpIdStatic(String ipId) {
        MrnUtil.ipId = ipId;
    }

    public static String getOrgShortNameFromOrgMrn(String orgMrn) {
        return MrnUtil.getEntityIdFromMrn(orgMrn);
    }

    public static String getOrgShortNameFromEntityMrn(String entityMrn) {
        String[] mrnSplit = entityMrn.split(":");
        return mrnSplit[5];
    }

    public static String getEntityIdFromMrn(String entityMrn) {
        String[] mrnSplit = entityMrn.split(":");
        return mrnSplit[mrnSplit.length - 1];
    }

    public static String getServiceTypeFromMrn(String serviceMrn) {
        if (!serviceMrn.contains(":instance:") || !serviceMrn.contains(":service:")) {
            throw new IllegalArgumentException("The MRN must belong to a service instance!");
        }
        String[] mrnSplit = serviceMrn.split(":");
        return mrnSplit[6];
    }

    public static boolean isNotMrnEmpty(String mrn) {
        return (mrn != null) && !(mrn.trim().isEmpty());
    }

    public static boolean validateMrn(String mrn) {
        return isNotMrnEmpty(mrn) && MRN_PATTERN.matcher(mrn).matches();
    }

    public static boolean validateMCPMrn(String mrn) {
        if(validateMrn(mrn) && MCP_MRN_PATTERN.matcher(mrn).matches()){
            String[] parts = mrn.split(":");
            if (!parts[4].equals(ipId)) {
                throw new IllegalArgumentException("MCP MRN does not contain the correct identity provider provider ID");
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
    public static String getMrnPrefix(String mrn) {
        // mrn always starts with 'urn:mrn:<sub-namespace>'
        int prefixEnd = mrn.indexOf(':', 8);
        return mrn.substring(0, prefixEnd);
    }

}
