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
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringRunner;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;
import java.util.Calendar;
import java.util.Date;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(SpringRunner.class)
public class CertificateRevocationTests {

    private Validator validator;

    @Before
    public void init() {
        ValidatorFactory vf = Validation.buildDefaultValidatorFactory();
        this.validator = vf.getValidator();
    }

    @Test
    public void validateInvalidCR() {
        // Set up a CR with invalid reason and date
        CertificateRevocation cr = new CertificateRevocation();
        cr.setRevokationReason("not-valid-reason");
        cr.setRevokedAt(null);
        // Try to validate the CR
        Set<ConstraintViolation<CertificateRevocation>> violations = validator.validate(cr);
        assertEquals(violations.size(), 2);
    }

    @Test
    public void validateValidCR() {
        // Set up a CR with valid reason and date
        CertificateRevocation cr = new CertificateRevocation();
        cr.setRevokationReason("certificatehold");
        Calendar cal = Calendar.getInstance();
        Date now = cal.getTime();
        cr.setRevokedAt(now);
        // Try to validate the CR
        Set<ConstraintViolation<CertificateRevocation>> violations = validator.validate(cr);
        assertTrue(violations.isEmpty());
    }


}
