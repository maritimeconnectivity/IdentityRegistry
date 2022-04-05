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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;

import static org.springframework.test.util.AssertionErrors.assertEquals;
import static org.springframework.test.util.AssertionErrors.assertFalse;
import static org.springframework.test.util.AssertionErrors.assertTrue;


@ExtendWith(SpringExtension.class)
@SpringBootTest
@ContextConfiguration
@WebAppConfiguration
@ActiveProfiles("test")
class MrnUtilsTests {

    @Autowired
    private MrnUtil mrnUtil;

    @Test
    void extractOrgShortnameFromOrgMRN1() {
        String orgMrn = "urn:mrn:mcp:org:idp1:dma";
        String ret = mrnUtil.getOrgShortNameFromOrgMrn(orgMrn);
        assertEquals("Org shortname should be 'dma'","dma", ret);
    }

    @Test
    void extractOrgShortnameFromOrgMRN2() {
        String orgMrn = "urn:mrn:mcp:org:idp1:dfds@bimco";
        String ret = mrnUtil.getOrgShortNameFromOrgMrn(orgMrn);
        assertEquals("Org shortname should be 'dfds@bimco'","dfds@bimco", ret);
    }

//    @Test
//    void extractOrgValidatorFromOrgShortname1() {
//        String orgMrn = "dfds@bimco";
//        String ret = mrnUtil.getOrgValidatorFromOrgShortname(orgMrn);
//        assertEquals("Org validator should be 'bimco'","bimco", ret);
//    }
//
//    @Test
//    void extractOrgValidatorFromOrgShortname2() {
//        String orgMrn = "bimco";
//        String ret = mrnUtil.getOrgValidatorFromOrgShortname(orgMrn);
//        assertEquals("Org validator should be 'maritimecloud-idreg'","maritimecloud-idreg", ret);
//    }

    @Test
    void extractOrgShortnameFromUserMRN1() {
        String userMrn = "urn:mrn:mcp:user:idp1:dma:b00345";
        String ret = mrnUtil.getOrgShortNameFromEntityMrn(userMrn);
        assertEquals("Org shortname should be 'dma'","dma", ret);
    }

    @Test
    void extractOrgShortnameFromUserMRN2() {
        String userMrn = "urn:mrn:mcp:user:idp1:dfds@bimco:fiskerfinn";
        String ret = mrnUtil.getOrgShortNameFromEntityMrn(userMrn);
        assertEquals("Org shortname should be 'dfds@bimco'","dfds@bimco", ret);
    }

    @Test
    void extractOrgShortnameFromUserMRN3() {
        String userMrn = "urn:mrn:mcp:user:thc";
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            mrnUtil.getOrgShortNameFromEntityMrn(userMrn);
        });
    }

    @Test
    void extractOrgShortnameFromVesselMRN1() {
        String userMrn = "urn:mrn:mcp:vessel:idp1:dma:poul-loewenoern";
        String ret = mrnUtil.getOrgShortNameFromEntityMrn(userMrn);
        assertEquals("Org shortname should be 'dma'","dma", ret);
    }

    @Test
    void extractOrgShortnameFromVesselMRN2() {
        String userMrn = "urn:mrn:mcp:user:idp1:dfds@bimco:crown-seaways";
        String ret = mrnUtil.getOrgShortNameFromEntityMrn(userMrn);
        assertEquals("Org shortname should be 'dfds@bimco'","dfds@bimco", ret);
    }

    @Test
    void extractUserIdFromUserMRN1() {
        String userMrn = "urn:mrn:mcp:user:idp1:dma:b00345";
        String ret = mrnUtil.getEntityIdFromMrn(userMrn);
        assertEquals("User id should be 'b00345'","b00345", ret);
    }

    @Test
    void extractUserIdFromUserMRN2() {
        String userMrn = "urn:mrn:mcp:user:idp1:dma:secretary:bob";
        String ret = mrnUtil.getEntityIdFromMrn(userMrn);
        assertEquals("User id should be 'secretary:bob'","secretary:bob", ret);
    }

    @Test
    void validatingServiceInstanceMRN1() {
        String userMrn = "urn:mrn:mcp:service:idp1:dma:instance:nw-nm-design:nw-nm-prod";
        boolean ret = mrnUtil.validateMCPMrn(userMrn);
        assertTrue("Service MRN should be valid", ret);
    }

    @Test
    void validatingOrgMRN1() {
        String orgMrn = "urn:mrn:mcp:org:idp1:dma";
        boolean ret = mrnUtil.validateMCPMrn(orgMrn);
        assertTrue("Org MRN should be valid", ret);
    }

    @Test
    void validatingOrgMRN2() {
        String orgMrn = "urn:x-mrn:mcl:org:dma";
        boolean result = mrnUtil.validateMrn(orgMrn);
        assertFalse("The MRN should not be valid", result);
    }

    @Test
    void validatingVesselMRN1() {
        String vesselMrn = "urn:mrn:mcp:vessel:idp1:dma:poul-loewenoern";
        boolean ret = mrnUtil.validateMCPMrn(vesselMrn);
        assertTrue("Vessel MRN should be valid", ret);
    }

    @Test
    void validatingVesselMRN2() {
        // Invalid mrn - special characters like "ø" are not allowed
        String vesselMrn = "urn:mrn:mcp:vessel:idp1:dma:poul-løwenørn";
        boolean result = mrnUtil.validateMrn(vesselMrn);
        assertFalse("The MRN should not be valid", result);
    }

    @Test
    void extractPrefixFromMRN() {
        String userMrn = "urn:mrn:mcl:service:instance:dma:nw-nm-prod";
        String prefix = mrnUtil.getMrnPrefix(userMrn);
        assertEquals("Prefix should be 'urn:mrn:mcl'","urn:mrn:mcl", prefix);
    }

    @Test
    void extractPrefixFromMRN2() {
        String userMrn = "urn:mrn:iala:device:iala:device6";
        String prefix = mrnUtil.getMrnPrefix(userMrn);
        assertEquals("Prefix should be 'urn:mrn:iala'","urn:mrn:iala", prefix);
    }

}
