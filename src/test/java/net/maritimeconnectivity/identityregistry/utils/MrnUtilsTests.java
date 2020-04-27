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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(SpringRunner.class)
public class MrnUtilsTests {

    @Test
    public void extractOrgShortnameFromOrgMRN1() {
        String orgMrn = "urn:mrn:mcl:org:dma";
        String ret = MrnUtil.getOrgShortNameFromOrgMrn(orgMrn);
        assertEquals("Org shortname should be 'dma'","dma", ret);
    }

    @Test
    public void extractOrgShortnameFromOrgMRN2() {
        String orgMrn = "urn:mrn:mcl:org:dfds@bimco";
        String ret = MrnUtil.getOrgShortNameFromOrgMrn(orgMrn);
        assertEquals("Org shortname should be 'dfds@bimco'","dfds@bimco", ret);
    }

//    @Test
//    public void extractOrgValidatorFromOrgShortname1() {
//        String orgMrn = "dfds@bimco";
//        String ret = MrnUtil.getOrgValidatorFromOrgShortname(orgMrn);
//        assertEquals("Org validator should be 'bimco'","bimco", ret);
//    }
//
//    @Test
//    public void extractOrgValidatorFromOrgShortname2() {
//        String orgMrn = "bimco";
//        String ret = MrnUtil.getOrgValidatorFromOrgShortname(orgMrn);
//        assertEquals("Org validator should be 'maritimecloud-idreg'","maritimecloud-idreg", ret);
//    }

    @Test
    public void extractOrgShortnameFromUserMRN1() {
        String userMrn = "urn:mrn:mcl:user:dma:b00345";
        String ret = MrnUtil.getOrgShortNameFromEntityMrn(userMrn);
        assertEquals("Org shortname should be 'dma'","dma", ret);
    }

    @Test
    public void extractOrgShortnameFromUserMRN2() {
        String userMrn = "urn:mrn:mcl:user:dfds@bimco:fiskerfinn";
        String ret = MrnUtil.getOrgShortNameFromEntityMrn(userMrn);
        assertEquals("Org shortname should be 'dfds@bimco'","dfds@bimco", ret);
    }

    @Test(expected=IllegalArgumentException.class)
    public void extractOrgShortnameFromUserMRN3() {
        String userMrn = "urn:mrn:mcl:user:thc";
        MrnUtil.getOrgShortNameFromEntityMrn(userMrn);
    }

    @Test
    public void extractOrgShortnameFromVesselMRN1() {
        String userMrn = "urn:mrn:mcl:vessel:dma:poul-loewenoern";
        String ret = MrnUtil.getOrgShortNameFromEntityMrn(userMrn);
        assertEquals("Org shortname should be 'dma'","dma", ret);
    }

    @Test
    public void extractOrgShortnameFromVesselMRN2() {
        String userMrn = "urn:mrn:mcl:user:dfds@bimco:crown-seaways";
        String ret = MrnUtil.getOrgShortNameFromEntityMrn(userMrn);
        assertEquals("Org shortname should be 'dfds@bimco'","dfds@bimco", ret);
    }

    @Test
    public void extractUserIdFromUserMRN1() {
        String userMrn = "urn:mrn:mcl:user:dma:b00345";
        String ret = MrnUtil.getEntityIdFromMrn(userMrn);
        assertEquals("User id should be 'b00345'","b00345", ret);
    }

    @Test(expected=IllegalArgumentException.class)
    public void extractServiceTypeFromServiceMRN1() {
        String userMrn = "urn:mrn:mcl:service:specification:dma:nw-nm-spec";
        MrnUtil.getServiceTypeFromMrn(userMrn);
    }

    @Test
    public void extractServiceTypeFromServiceMRN2() {
        String userMrn = "urn:mrn:mcl:org:dma:service:instance:nw-nm-design:nw-nm-prod";
        String ret = MrnUtil.getServiceTypeFromMrn(userMrn);
        assertEquals("Service type should be 'nw-nm-design'","nw-nm-design", ret);
    }

    @Test
    public void validatingServiceInstanceMRN1() {
        String userMrn = "urn:mrn:mcl:org:dma:service:instance:nw-nm-design:nw-nm-prod";
        boolean ret = MrnUtil.validateMrn(userMrn);
        assertTrue("Service MRN should be valid", ret);
    }

    @Test
    public void validatingOrgMRN1() {
        String orgMrn = "urn:mrn:mcl:org:dma";
        boolean ret = MrnUtil.validateMrn(orgMrn);
        assertTrue("Org MRN should be valid", ret);
    }

    @Test(expected=IllegalArgumentException.class)
    public void validatingOrgMRN2() {
        String orgMrn = "urn:x-mrn:mcl:org:dma";
        MrnUtil.validateMrn(orgMrn);
    }

    @Test
    public void validatingVesselMRN1() {
        String vesselMrn = "urn:mrn:mcl:org:dma:vessel:poul-loewenoern";
        boolean ret = MrnUtil.validateMrn(vesselMrn);
        assertTrue("Vessel MRN should be valid", ret);
    }

    @Test(expected=IllegalArgumentException.class)
    public void validatingVesselMRN2() {
        // Invalid mrn - special characters like "ø" are not allowed
        String vesselMrn = "urn:mrn:mcl:org:dma:vessel:poul-løwenørn";
        MrnUtil.validateMrn(vesselMrn);
    }

    @Test
    public void extractPrefixFromMRN() {
        String userMrn = "urn:mrn:mcl:service:instance:dma:nw-nm-prod";
        String prefix = MrnUtil.getMrnPrefix(userMrn);
        assertEquals("Prefix should be 'urn:mrn:mcl'","urn:mrn:mcl", prefix);
    }

    @Test
    public void extractPrefixFromMRN2() {
        String userMrn = "urn:mrn:iala:device:iala:device6";
        String prefix = MrnUtil.getMrnPrefix(userMrn);
        assertEquals("Prefix should be 'urn:mrn:iala'","urn:mrn:iala", prefix);
    }

}
