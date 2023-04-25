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
package net.maritimeconnectivity.identityregistry.validators;

import net.maritimeconnectivity.identityregistry.model.database.entities.Vessel;
import net.maritimeconnectivity.identityregistry.model.database.entities.VesselAttribute;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.springframework.web.context.WebApplicationContext;

import jakarta.validation.ConstraintViolation;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@ContextConfiguration
@WebAppConfiguration
@ActiveProfiles("test")
class VesselValidatorTests {
    @Autowired
    private WebApplicationContext context;

    private LocalValidatorFactoryBean validator;

    @MockBean
    JwtDecoder jwtDecoder;

    @BeforeEach
    void init() {
        validator = context.getBean(LocalValidatorFactoryBean.class);
    }

    @Test
    void validateInvalidVesselNoVesselOrgId() {
        Vessel invalidVessel = new Vessel();
        invalidVessel.setName("Test Vessel");
        Set<ConstraintViolation<Vessel>> violations = validator.validate(invalidVessel);
        assertEquals(1, violations.size());
    }

    @Test
    void validateInvalidVesselNoName() {
        Vessel invalidVessel = new Vessel();
        invalidVessel.setMrn("urn:mrn:mcp:vessel:idp1:testorg:invalid-vessel");
        Set<ConstraintViolation<Vessel>> violations = validator.validate(invalidVessel);
        assertEquals(1, violations.size());
    }

    @Test
    void validateValidVesselNoAttributes() {
        Vessel validVessel = new Vessel();
        validVessel.setMrn("urn:mrn:mcp:vessel:idp1:test-org:valid-vessel");
        validVessel.setName("Test Vessel");
        Set<ConstraintViolation<Vessel>> violations = validator.validate(validVessel);
        assertEquals(0, violations.size());
    }

    @Test
    void validateValidVesselWithAttributes() {
        Vessel validVessel = new Vessel();
        validVessel.setMrn("urn:mrn:mcp:vessel:idp1:test:valid-vessel");
        validVessel.setName("Test Vessel");
        VesselAttribute va1 = new VesselAttribute();
        va1.setAttributeName("flagstate");
        va1.setAttributeValue("Denmark");
        VesselAttribute va2 = new VesselAttribute();
        va2.setAttributeName("imo-number");
        va2.setAttributeValue("1234567");
        validVessel.setAttributes(new HashSet<>(Arrays.asList(va1, va2)));
        Set<ConstraintViolation<Vessel>> violations = validator.validate(validVessel);
        assertEquals(0, violations.size());
    }

    @Test
    void validateInvalidVesselWithAttributes() {
        Vessel invalidVessel = new Vessel();
        invalidVessel.setMrn("urn:mrn:mcp:vessel:idp1:test:invalid-vessel");
        invalidVessel.setName("Test Vessel");
        VesselAttribute va1 = new VesselAttribute();
        // Invalid attribute: value must not be empty
        va1.setAttributeName("flagstate");
        va1.setAttributeValue(null);
        VesselAttribute va2 = new VesselAttribute();
        // Invalid attribute: must be one of the pre-defined values
        va2.setAttributeName(null);
        va2.setAttributeValue("1234567");
        invalidVessel.setAttributes(new HashSet<>(Arrays.asList(va1, va2)));
        Set<ConstraintViolation<Vessel>> violations = validator.validate(invalidVessel);
        assertEquals(2, violations.size());
    }

}
