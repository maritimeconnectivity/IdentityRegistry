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

import net.maritimecloud.identityregistry.model.database.entities.User;
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
public class UserValidatorTests {

    private Validator validator;

    @Before
    public void init() {
        ValidatorFactory vf = Validation.buildDefaultValidatorFactory();
        this.validator = vf.getValidator();
    }

    @Test
    public void validateValidUser() {
        User validUser = new User();
        validUser.setFirstName("Firstname");
        validUser.setLastName("Lastname");
        validUser.setEmail("user@test.org");
        validUser.setUserOrgId("org.userId");

        Set<ConstraintViolation<User>> violations = validator.validate(validUser);
        assertTrue(violations.isEmpty());
    }

    @Test
    public void validateInvalidUser1() {
        User invalidUser = new User();
        invalidUser.setFirstName("Firstname");
        // Invalid lastname - must be filled
        invalidUser.setLastName(" ");
        // Invalid email
        invalidUser.setEmail("user-test.org");
        invalidUser.setUserOrgId("org.userId");

        Set<ConstraintViolation<User>> violations = validator.validate(invalidUser);
        assertTrue(violations.size() == 2);
    }

    @Test
    public void validateInvalidUser2() {
        User invalidUser = new User();
        invalidUser.setFirstName("Firstname");
        invalidUser.setLastName("Lastname");
        invalidUser.setEmail("user@test.org");
        // Invalid userOrgId, must be in the format ORG_SHORTNAME.USER_ID
        invalidUser.setUserOrgId("org-userId");

        Set<ConstraintViolation<User>> violations = validator.validate(invalidUser);
        assertTrue(violations.size() == 1);
    }

}
