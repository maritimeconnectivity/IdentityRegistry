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
package net.maritimecloud.identityregistry.utils;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@WebAppConfiguration
public class MrnUtilsTests {

    @Test
    public void extractOrgShortnameFromOrgMRN1() {
        String orgMrn = "urn:mrn:mcl:org:dma";
        String ret = MrnUtils.getOrgShortNameFromOrgMrn(orgMrn);
        assertEquals("Org shortname should be 'dma'","dma", ret);
    }

    @Test
    public void extractOrgShortnameFromOrgMRN2() {
        String orgMrn = "urn:mrn:mcl:org:bimco:member:dfds";
        String ret = MrnUtils.getOrgShortNameFromOrgMrn(orgMrn);
        assertEquals("Org shortname should be 'dfds'","dfds", ret);
    }

    @Test
    public void extractOrgValidatorFromOrgMrn1() {
        String orgMrn = "urn:mrn:mcl:org:bimco:member:dfds";
        String ret = MrnUtils.getOrgValidatorFromOrgMrn(orgMrn);
        assertEquals("Org validator should be 'bimco'","bimco", ret);
    }

    @Test
    public void extractOrgValidatorFromOrgMrn2() {
        String orgMrn = "urn:mrn:mcl:org:bimco";
        String ret = MrnUtils.getOrgValidatorFromOrgMrn(orgMrn);
        assertEquals("Org validator should be 'mcl'","mcl", ret);
    }

    @Test
    public void extractOrgShortnameFromUserMRN1() {
        String userMrn = "urn:mrn:mcl:org:dma:user:b00345";
        String ret = MrnUtils.getOrgShortNameFromEntityMrn(userMrn);
        assertEquals("Org shortname should be 'dma'","dma", ret);
    }

    @Test
    public void extractOrgShortnameFromUserMRN2() {
        String userMrn = "urn:mrn:mcl:org:bimco:member:dfds:user:fiskerfinn";
        String ret = MrnUtils.getOrgShortNameFromEntityMrn(userMrn);
        assertEquals("Org shortname should be 'dfds'","dfds", ret);
    }

    @Test
    public void extractOrgShortnameFromVesselMRN1() {
        String userMrn = "urn:mrn:mcl:org:dma:vessel:poul-loewenoern";
        String ret = MrnUtils.getOrgShortNameFromEntityMrn(userMrn);
        assertEquals("Org shortname should be 'dma'","dma", ret);
    }

    @Test
    public void extractOrgShortnameFromVesselMRN2() {
        String userMrn = "urn:mrn:mcl:org:bimco:member:dfds:vessel:crown-seaways";
        String ret = MrnUtils.getOrgShortNameFromEntityMrn(userMrn);
        assertEquals("Org shortname should be 'dfds'","dfds", ret);
    }

    @Test
    public void extractOrgMRNFromVesselMRN1() {
        String vesselMrn = "urn:mrn:mcl:org:dma:vessel:poul-loewenoern";
        String ret = MrnUtils.getOrgMrnEntityMrn(vesselMrn);
        assertEquals("Org shortname should be 'urn:mrn:mcl:org:dma'","urn:mrn:mcl:org:dma", ret);
    }

    @Test
    public void extractOrgMRNFromVesselMRN2() {
        String vesselMrn = "urn:mrn:mcl:org:bimco:member:dfds:vessel:crown-seaways";
        String ret = MrnUtils.getOrgMrnEntityMrn(vesselMrn);
        assertEquals("Org shortname should be 'urn:mrn:mcl:org:bimco:member:dfds'","urn:mrn:mcl:org:bimco:member:dfds", ret);
    }

    @Test
    public void extractUserIdFromUserMRN1() {
        String userMrn = "urn:mrn:mcl:org:dma:user:b00345";
        String ret = MrnUtils.getEntityIdFromMrn(userMrn);
        assertEquals("User id should be 'b00345'","b00345", ret);
    }

    @Test(expected=IllegalArgumentException.class)
    public void extractServiceTypeFromServiceMRN1() {
        String userMrn = "urn:mrn:mcl:org:dma:service:nw-nm:specification";
        String ret = MrnUtils.getServiceTypeFromMrn(userMrn);
    }

    @Test
    public void extractServiceTypeFromServiceMRN2() {
        String userMrn = "urn:mrn:mcl:org:dma:service:nw-nm:instance:nw-nm-prod";
        String ret = MrnUtils.getServiceTypeFromMrn(userMrn);
        assertEquals("Service type should be 'nw-nm'","nw-nm", ret);
    }

    @Test
    public void validatingServiceInstanceMRN1() {
        String userMrn = "urn:mrn:mcl:org:dma:service:nw-nm:instance:nw-nm-prod";
        boolean ret = MrnUtils.validateMrn(userMrn);
        assertTrue("Service MRN should be valid", ret);
    }

    @Test
    public void validatingOrgMRN1() {
        String orgMrn = "urn:mrn:mcl:org:dma";
        boolean ret = MrnUtils.validateMrn(orgMrn);
        assertTrue("Org MRN should be valid", ret);
    }

    @Test(expected=IllegalArgumentException.class)
    public void validatingOrgMRN2() {
        String orgMrn = "urn:x-mrn:mcl:org:dma";
        boolean ret = MrnUtils.validateMrn(orgMrn);
    }

    @Test
    public void validatingVesselMRN1() {
        String vesselMrn = "urn:mrn:mcl:org:dma:vessel:poul-loewenoern";
        boolean ret = MrnUtils.validateMrn(vesselMrn);
        assertTrue("Vessel MRN should be valid", ret);
    }

    @Test(expected=IllegalArgumentException.class)
    public void validatingVesselMRN2() {
        // Invalid mrn - special characters like "ø" are not allowed
        String vesselMrn = "urn:mrn:mcl:org:dma:vessel:poul-løwenørn";
        boolean ret = MrnUtils.validateMrn(vesselMrn);
    }

}
