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
package net.maritimecloud.identityregistry.validators;

import net.maritimecloud.identityregistry.model.database.entities.Vessel;
import net.maritimecloud.identityregistry.model.database.entities.VesselAttribute;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.Errors;

import java.util.Arrays;

import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@WebAppConfiguration
public class VesselValidatorTests {

    @Autowired
    private VesselValidator vesselValidator;

    @Test
    public void validateInvalidVesselNoVesselOrgId() {
        Vessel invalidVessel = new Vessel();
        invalidVessel.setName("Test Vessel");
        Errors errors = new BeanPropertyBindingResult(invalidVessel, "invalidVessel");
        this.vesselValidator.validate(invalidVessel, errors);
        assertTrue(errors.hasErrors());
    }

    @Test
    public void validateInvalidVesselNoName() {
        Vessel invalidVessel = new Vessel();
        invalidVessel.setVesselOrgId("Vessel1");
        Errors errors = new BeanPropertyBindingResult(invalidVessel, "invalidVessel");
        this.vesselValidator.validate(invalidVessel, errors);
        assertTrue(errors.hasErrors());
    }

    @Test
    public void validateValidVesselNoAttributes() {
        Vessel validVessel = new Vessel();
        validVessel.setVesselOrgId("Vessel1");
        validVessel.setName("Test Vessel");
        Errors errors = new BeanPropertyBindingResult(validVessel, "validVessel");
        this.vesselValidator.validate(validVessel, errors);
        assertFalse(errors.hasErrors());
    }

    @Test
    public void validateValidVesselWithAttributes() {
        Vessel validVessel = new Vessel();
        validVessel.setVesselOrgId("Vessel1");
        validVessel.setName("Test Vessel");
        VesselAttribute va1 = new VesselAttribute();
        va1.setAttributeName("flagstate");
        va1.setAttributeValue("Denmark");
        VesselAttribute va2 = new VesselAttribute();
        va2.setAttributeName("imo-number");
        va2.setAttributeValue("1234567");
        validVessel.setAttributes(Arrays.asList(va1, va2));
        Errors errors = new BeanPropertyBindingResult(validVessel, "validVessel");
        this.vesselValidator.validate(validVessel, errors);
        assertFalse(errors.hasErrors());
    }

    @Test
    public void validateInvalidVesselWithAttributes() {
        Vessel invalidVessel = new Vessel();
        invalidVessel.setVesselOrgId("Vessel1");
        invalidVessel.setName("Test Vessel");
        VesselAttribute va1 = new VesselAttribute();
        // Invalid attribute: value must not be empty
        va1.setAttributeName("flagstate");
        va1.setAttributeValue("");
        VesselAttribute va2 = new VesselAttribute();
        // Invalid attribute: must be one of the pre-defined values
        va2.setAttributeName(null);
        va2.setAttributeValue("1234567");
        invalidVessel.setAttributes(Arrays.asList(va1, va2));
        Errors errors = new BeanPropertyBindingResult(invalidVessel, "invalidVessel");
        this.vesselValidator.validate(invalidVessel, errors);
        assertTrue(errors.hasErrors());
        assertTrue(errors.getErrorCount() == 2);
    }

}
