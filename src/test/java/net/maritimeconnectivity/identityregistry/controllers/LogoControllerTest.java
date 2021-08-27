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
package net.maritimeconnectivity.identityregistry.controllers;

import com.google.common.collect.Lists;
import net.maritimeconnectivity.identityregistry.model.database.Logo;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.repositories.OrganizationRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.springframework.web.context.WebApplicationContext;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.validation.ConstraintViolation;
import java.util.List;
import java.util.Set;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.util.AssertionErrors.assertEquals;
import static org.springframework.test.util.AssertionErrors.assertNull;

/**
 * @author Klaus Groenbaek
 *         Created 03/03/17.
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest
@ContextConfiguration
@WebAppConfiguration
class LogoControllerTest {
    @Autowired
    private WebApplicationContext context;

    @Autowired
    LogoController logoController;

    @Autowired
    OrganizationRepository orgRepo;

    @Autowired
    EntityManagerFactory emf;

    private LocalValidatorFactoryBean validator;

    @BeforeEach
    void init() {
        validator = context.getBean(LocalValidatorFactoryBean.class);
    }

    @Test
    void deleteLogo() throws Exception {

        assertNumberOfLogos(0);

        Organization org = new Organization();
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        org.setApproved(true);
        org.setFederationType("external-idp");
        org.setCertificateAuthority("TEST_CA");
        Logo logo = new Logo();
        logo.setImage(new byte[]{1, 2, 3});
        org.setLogo(logo);
        Set<ConstraintViolation<Organization>> violations = validator.validate(org);
        assertEquals("Number of logos", 0, violations.size());

        orgRepo.save(org);

        // fiddle with security to be able to call the delete method
        InetOrgPerson person = mock(InetOrgPerson.class);
        when(person.getO()).then(invocation -> org.getMrn());
        Authentication previousAuth = SecurityContextHolder.getContext().getAuthentication();
        SecurityContextHolder.getContext().setAuthentication(new PreAuthenticatedAuthenticationToken(person, "",
                Lists.newArrayList(new SimpleGrantedAuthority("ROLE_ORG_ADMIN"))));

        try {
            logoController.deleteLogo(new MockHttpServletRequest("DELETE", "/path"), org.getMrn());

            Organization reloaded = orgRepo.findByMrn(org.getMrn());
            assertNull("Logo should be deleted", reloaded.getLogo());

            assertNumberOfLogos(0);
        } finally {
            SecurityContextHolder.getContext().setAuthentication(previousAuth);
        }
    }

    private void assertNumberOfLogos(int expectedLogoCount) {
        EntityManager em = emf.createEntityManager();
        try {
            List<Logo> logos = em.createQuery("select l from Logo l", Logo.class).getResultList();
            assertEquals("Number of logos", expectedLogoCount, logos.size());
        } catch (Exception e) {
            em.close();
        }
    }

}
