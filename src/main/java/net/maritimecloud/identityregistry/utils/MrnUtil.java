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

import java.util.regex.Pattern;

/**
 * Utility class to create, validate and extract certain info from MRNs
 */
public class MrnUtil {

    public final static Pattern MRN_PATTERN = Pattern.compile("^urn:mrn:([a-z0-9()+,\\-.:=@;$_!*']|%[0-9a-f]{2})+$", Pattern.CASE_INSENSITIVE);
    public final static Pattern MRN_SERVICE_INSTANCE_PATTERN = Pattern.compile("^urn:mrn:([a-z0-9()+,\\-.:=@;$_!*']|%[0-9a-f]{2})+?:service:instance:([a-z0-9()+,\\-.:=@;$_!*']|%[0-9a-f]{2})+$", Pattern.CASE_INSENSITIVE);
    public final static Pattern MRN_USER_PATTERN = Pattern.compile("^urn:mrn:([a-z0-9()+,\\-.:=@;$_!*']|%[0-9a-f]{2})+?:user:([a-z0-9()+,\\-.:=@;$_!*']|%[0-9a-f]{2})+$", Pattern.CASE_INSENSITIVE);
    public final static Pattern MRN_VESSEL_PATTERN = Pattern.compile("^urn:mrn:([a-z0-9()+,\\-.:=@;$_!*']|%[0-9a-f]{2})+?:vessel:([a-z0-9()+,\\-.:=@;$_!*']|%[0-9a-f]{2})+$", Pattern.CASE_INSENSITIVE);
    public final static Pattern MRN_DEVICE_PATTERN = Pattern.compile("^urn:mrn:([a-z0-9()+,\\-.:=@;$_!*']|%[0-9a-f]{2})+?:device:([a-z0-9()+,\\-.:=@;$_!*']|%[0-9a-f]{2})+$", Pattern.CASE_INSENSITIVE);

    private MrnUtil() {
    }

    public static String getOrgShortNameFromOrgMrn(String orgMrn) {
        int idx = orgMrn.lastIndexOf(":") + 1;
        return orgMrn.substring(idx);
    }

    /**
     * Returns the org shortname of the organization responsible for validating the organization that is
     * identified by the given shortname. If MCP is the validator "maritimecloud-idreg" is returned.
     * @param orgShortname
     * @return
     */
    public static String getOrgValidatorFromOrgShortname(String orgShortname) {
        if (orgShortname.contains("@")) {
            // This handles the nested validators
            String[] dividedShotname = orgShortname.split("@", 2);
            return dividedShotname[1];
        } else {
            // this shouldn't be hardcoded
            return "maritimecloud-idreg";
        }
    }

    public static String getOrgShortNameFromEntityMrn(String entityMrn) {
        // An entity MRN looks like this: urn:mrn:mcl:user:<org-shortname>:<user-id>
        int tmpIdx = entityMrn.indexOf(":user:");
        int startIdx = tmpIdx + 6;
        if (tmpIdx < 0) {
            tmpIdx = entityMrn.indexOf(":device:");
            startIdx = tmpIdx + 8;
        }
        if (tmpIdx < 0) {
            tmpIdx = entityMrn.indexOf(":vessel:");
            startIdx = tmpIdx + 8;
        }
        if (tmpIdx < 0) {
            tmpIdx = entityMrn.indexOf(":service:instance:");
            startIdx = tmpIdx + 18;
        }
        if (tmpIdx < 0) {
            throw new IllegalArgumentException("MRN is not a valid entity MRN!");
        }
        int endIdx = entityMrn.indexOf(":", startIdx);
        if (endIdx < 0) {
            throw new IllegalArgumentException("MRN is not a valid entity MRN!");
        }
        return entityMrn.substring(startIdx, endIdx);
    }

    public static String getEntityIdFromMrn(String entityMrn) {
        int idx = entityMrn.lastIndexOf(":") + 1;
        return entityMrn.substring(idx);
    }

    public static String getServiceTypeFromMrn(String serviceMrn) {
        if (!serviceMrn.contains(":instance:") || !serviceMrn.contains(":service:")) {
            throw new IllegalArgumentException("The MRN must belong to a service instance!");
        }
        int startIdx = serviceMrn.indexOf(":service:instance:") + 18;
        int endIdx = serviceMrn.indexOf(":", startIdx);
        return serviceMrn.substring(startIdx, endIdx);
    }

    // not used right now
    /*public static String generateMrnForEntity(String orgMrn, String type, String entityId) {
        // clean entity id, replace reserved URN characters with "_"
        // others: "()+,-.:=@;$_!*'"   reserved: "%/?#"
        entityId = entityId.replaceAll("[()+,-.:=@;$_!*'%/??#]", "_"); // double questionmark as escape
        String mrn = "";
        if ("service".equals(type)) {
            // <org-mrn>:service:<service-design-or-spec-id>:instance:<instance-id>
            // urn:mrn:mcl:org:dma:service:nw-nm:instance:nw-nm2
            throw new IllegalArgumentException("Generating MRN for services is not supported");
        } else {
            mrn = getMrnPrefix(orgMrn) + ":" + type + ":" + getOrgShortNameFromOrgMrn(orgMrn) + ":" + entityId;
        }
        return mrn;
    }*/

    public static boolean validateMrn(String mrn) {
        if (mrn == null || mrn.trim().isEmpty()) {
            throw new IllegalArgumentException("MRN is empty");
        }
        if (!MRN_PATTERN.matcher(mrn).matches()) {
            throw new IllegalArgumentException("MRN is not in a valid format");
        }
        // validate mrn based on the entity type
        if (mrn.contains(":service:") && !MRN_SERVICE_INSTANCE_PATTERN.matcher(mrn).matches()) {
            throw new IllegalArgumentException("MRN is not in a valid format for a service instances");
        } else if (mrn.contains(":user:") && !MRN_USER_PATTERN.matcher(mrn).matches()) {
            throw new IllegalArgumentException("MRN is not in a valid format for a user");
        } else if (mrn.contains(":vessel:") && !MRN_VESSEL_PATTERN.matcher(mrn).matches()) {
            throw new IllegalArgumentException("MRN is not in a valid format for a vessel");
        } else if (mrn.contains(":device:") && !MRN_DEVICE_PATTERN.matcher(mrn).matches()) {
            throw new IllegalArgumentException("MRN is not in a valid format for a device");
        }
        return true;
    }

    /**
     * Get MRN prefix. Would be 'urn:mrn:mcl' for 'urn:mrn:mcl:org:dma', and 'urn:mrn:stm' for 'urn:mrn:stm:user:sma:user42'
     * @param mrn
     * @return
     */
    public static String getMrnPrefix(String mrn) {
        // mrn always starts with 'urn:mrn:<sub-namespace>'
        int prefixEnd = mrn.indexOf(":", 8);
        return mrn.substring(0, prefixEnd);
    }

}
