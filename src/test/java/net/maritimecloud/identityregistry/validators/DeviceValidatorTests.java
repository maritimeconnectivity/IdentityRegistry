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


import net.maritimecloud.identityregistry.model.database.entities.Device;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;
import java.util.Set;

import static org.junit.Assert.assertTrue;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@WebAppConfiguration
public class DeviceValidatorTests {
    private Validator validator;

    @Before
    public void init() {
        ValidatorFactory vf = Validation.buildDefaultValidatorFactory();
        this.validator = vf.getValidator();
    }

    @Test
    public void validateValidDevice() {
        Device validDevice = new Device();
        validDevice.setDeviceOrgId("Device1");
        validDevice.setName("Test Device");

        Set<ConstraintViolation<Device>> violations = validator.validate(validDevice);
        assertTrue(violations.isEmpty());
    }

    @Test
    public void validateInvalidDevice() {
        Device invalidDevice = new Device();
        // Invalid deviceOrgId - must be set!
        invalidDevice.setDeviceOrgId(null);
        invalidDevice.setName("Test Device");

        Set<ConstraintViolation<Device>> violations = validator.validate(invalidDevice);
        assertTrue(violations.size() == 1);
    }

}
