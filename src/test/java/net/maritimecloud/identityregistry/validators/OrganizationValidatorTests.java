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


import net.maritimecloud.identityregistry.model.database.IdentityProviderAttribute;
import net.maritimecloud.identityregistry.model.database.Organization;
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
import java.util.Arrays;
import java.util.Set;

import static org.junit.Assert.assertTrue;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@WebAppConfiguration
public class OrganizationValidatorTests {

    private Validator validator;

    @Before
    public void init() {
        ValidatorFactory vf = Validation.buildDefaultValidatorFactory();
        this.validator = vf.getValidator();
    }

    @Test
    public void validateValidOrg() {
        Organization validOrg = new Organization();
        validOrg.setName("Test Org");
        validOrg.setShortName("TEST");
        validOrg.setAddress("Test address");
        validOrg.setCountry("Test Country");
        validOrg.setEmail("email@test.org");
        validOrg.setUrl("http://test.org");

        Set<ConstraintViolation<Organization>> violations = validator.validate(validOrg);
        assertTrue(violations.isEmpty());
    }

    @Test
    public void validateInvalidOrg1() {
        Organization invalidOrg = new Organization();
        invalidOrg.setName("Test Org");
        invalidOrg.setShortName("TEST");
        invalidOrg.setAddress("Test address");
        invalidOrg.setCountry("Test Country");
        // Invalid email!
        invalidOrg.setEmail("email-test.org");
        // Invalid URL
        invalidOrg.setUrl("http//test.org");

        Set<ConstraintViolation<Organization>> violations = validator.validate(invalidOrg);
        assertTrue(violations.size() == 2);
    }

    @Test
    public void validateInvalidOrg2() {
        Organization invalidOrg = new Organization();
        invalidOrg.setName("Test Org");
        // Invalid shortname - only 10 chars
        invalidOrg.setShortName("TESTTOOLONG");
        invalidOrg.setAddress("Test address");
        // Invalid country - must not be empty
        invalidOrg.setCountry(null);
        invalidOrg.setEmail("email@test.org");
        invalidOrg.setUrl("http://test.org");

        Set<ConstraintViolation<Organization>> violations = validator.validate(invalidOrg);
        assertTrue(violations.size() == 2);
    }

    @Test
    public void validateValidOrgWithIDP() {
        Organization validOrg = new Organization();
        validOrg.setName("Test Org");
        validOrg.setShortName("TEST");
        validOrg.setAddress("Test address");
        validOrg.setCountry("Test Country");
        validOrg.setEmail("email@test.org");
        validOrg.setUrl("http://test.org");
        IdentityProviderAttribute attr = new IdentityProviderAttribute();
        attr.setAttributeName("importUrl");
        attr.setAttributeValue("qwerty");
        validOrg.setIdentityProviderAttributes(Arrays.asList(attr));

        Set<ConstraintViolation<Organization>> violations = validator.validate(validOrg);
        assertTrue(violations.isEmpty());
    }

    @Test
    public void validateInvalidOrgWithIDP() {
        Organization invalidOrg = new Organization();
        invalidOrg.setName("Test Org");
        invalidOrg.setShortName("TEST");
        invalidOrg.setAddress("Test address");
        invalidOrg.setCountry("Test Country");
        invalidOrg.setEmail("email@test.org");
        invalidOrg.setUrl("http://test.org");
        IdentityProviderAttribute attr1 = new IdentityProviderAttribute();
        // Invalid attribute name
        attr1.setAttributeName("invalidAttr");
        attr1.setAttributeValue("qwerty");
        IdentityProviderAttribute attr2 = new IdentityProviderAttribute();
        // Invalid attribute value
        attr2.setAttributeName("importUrl");
        attr2.setAttributeValue("");

        invalidOrg.setIdentityProviderAttributes(Arrays.asList(attr1, attr2));

        Set<ConstraintViolation<Organization>> violations = validator.validate(invalidOrg);
        assertTrue(violations.size() == 2);
    }

}
