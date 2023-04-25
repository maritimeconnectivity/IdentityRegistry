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


import net.maritimeconnectivity.identityregistry.model.data.CertificateRevocation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import java.util.Calendar;
import java.util.Date;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


@ExtendWith(SpringExtension.class)
@ActiveProfiles("test")
class CertificateRevocationTests {

    @MockBean
    JwtDecoder jwtDecoder;

    private Validator validator;

    @BeforeEach
    void init() {
        ValidatorFactory vf = Validation.buildDefaultValidatorFactory();
        this.validator = vf.getValidator();
    }

    @Test
    void validateInvalidCR() {
        // Set up a CR with invalid reason and date
        CertificateRevocation cr = new CertificateRevocation();
        cr.setRevocationReason("not-valid-reason");
        cr.setRevokedAt(null);
        // Try to validate the CR
        Set<ConstraintViolation<CertificateRevocation>> violations = validator.validate(cr);
        assertEquals(2, violations.size());
    }

    @Test
    void validateValidCR() {
        // Set up a CR with valid reason and date
        CertificateRevocation cr = new CertificateRevocation();
        cr.setRevocationReason("certificatehold");
        Calendar cal = Calendar.getInstance();
        Date now = cal.getTime();
        cr.setRevokedAt(now);
        // Try to validate the CR
        Set<ConstraintViolation<CertificateRevocation>> violations = validator.validate(cr);
        assertTrue(violations.isEmpty());
    }


}
