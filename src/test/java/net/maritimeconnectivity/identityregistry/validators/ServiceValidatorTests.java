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

import net.maritimeconnectivity.identityregistry.model.database.entities.Service;
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
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


@ExtendWith(SpringExtension.class)
@SpringBootTest
@ContextConfiguration
@WebAppConfiguration
@ActiveProfiles("test")
class ServiceValidatorTests {
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
    void validateValidService() {
        Service validService = new Service();
        validService.setName("Test service");
        validService.setMrn("urn:mrn:mcp:service:idp1:testorg:instance:test-design:test-service-instance");
        validService.setOidcAccessType("bearer-only");
        validService.setOidcRedirectUri("http://test-redirect-url-to-service.net");
        validService.setInstanceVersion("0.3.4.a,d+e-g_h:y");
        Set<ConstraintViolation<Service>> violations = validator.validate(validService);
        assertTrue(violations.isEmpty());
    }

    @Test
    void validateInvalidService() {
        Service invalidService = new Service();
        invalidService.setName("Test service");
        // Invalid MRN service instances format
        invalidService.setMrn("urn:mrn:mcp:idp1:service:test:instance:test-service");
        // Invalid access type
        invalidService.setOidcAccessType("just rubish");
        // Invalid version format
        invalidService.setInstanceVersion("0.3.4/4");
        Set<ConstraintViolation<Service>> violations = validator.validate(invalidService);
        assertEquals(3, violations.size());
    }
}
