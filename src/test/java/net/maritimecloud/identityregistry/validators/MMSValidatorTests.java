/*
 * Copyright 2020 Maritime Connectivity Platform Consortium.
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

import net.maritimecloud.identityregistry.model.database.entities.MMS;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringRunner;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(SpringRunner.class)
public class MMSValidatorTests {
    private Validator validator;

    @Before
    public void init() {
        ValidatorFactory vf = Validation.buildDefaultValidatorFactory();
        this.validator = vf.getValidator();
    }

    @Test
    public void validateValidMMS() {
        MMS validMms = new MMS();
        validMms.setMrn("urn:mrn:mcl:mms:testorg:test-mms1");
        validMms.setName("Test mms");
        validMms.setUrl("http://maritimeconnectivity.net");

        Set<ConstraintViolation<MMS>> violations = validator.validate(validMms);
        assertTrue(violations.isEmpty());
    }

    @Test
    public void validateInvalidMMS() {
        MMS invalidMms = new MMS();
        invalidMms.setMrn("urn:mrn:mcl:mms:testorg:test-mms1");
        invalidMms.setName("Test mms");
        // Invalid url - must be set!
        invalidMms.setUrl(null);

        Set<ConstraintViolation<MMS>> violations = validator.validate(invalidMms);
        assertEquals(violations.size(), 1);
    }

}
