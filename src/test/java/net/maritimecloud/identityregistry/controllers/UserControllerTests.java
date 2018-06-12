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

package net.maritimecloud.identityregistry.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.maritimecloud.identityregistry.exception.McBasicRestException;
import net.maritimecloud.identityregistry.model.database.IdentityProviderAttribute;
import net.maritimecloud.identityregistry.model.database.Organization;
import net.maritimecloud.identityregistry.model.database.entities.User;
import net.maritimecloud.identityregistry.services.CertificateService;
import net.maritimecloud.identityregistry.services.EntityService;
import net.maritimecloud.identityregistry.services.OrganizationService;
import net.maritimecloud.identityregistry.utils.KeycloakAdminUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.subethamail.wiser.Wiser;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@ContextConfiguration
@WebAppConfiguration
public class UserControllerTests {
    @Autowired
    private WebApplicationContext context;

    private MockMvc mvc;
    @MockBean
    private EntityService<User> entityService;

    @MockBean
    private OrganizationService organizationService;

    @MockBean
    private KeycloakAdminUtil keycloakAU;

    @MockBean
    private CertificateService certificateService;

    @Before
    public void setup() {
        mvc = MockMvcBuilders
                .webAppContextSetup(context)
                //.alwaysDo(print())
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    /**
     * Try to get a user without being authenticated
     */
    @WithMockUser()
    @Test
    public void testAccessGetUserWithoutRights() {
        given(this.entityService.getByMrn("urn:mrn:mcl:user:dma:thc")).willReturn(new User());
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcl:org:dma/user/urn:mrn:mcl:user:dma:thc").header("Origin", "bla")).andExpect(status().isForbidden());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Try to get a user with the appropriate association
     */
    @Test
    public void testAccessGetUserWithRights() {
        // Build user object to test with
        User user = new User();
        user.setMrn("urn:mrn:mcl:user:dma:thc");
        user.setFirstName("Thomas");
        user.setLastName("Christensen");
        user.setIdOrganization(1l);
        user.setEmail("thcc@dma.dk");
        String userJson = serialize(user);
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcl:org:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Create fake authentication token
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcl:org:dma", "ROLE_USER", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcl:org:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcl:user:dma:thc")).willReturn(user);
        when(org.getId()).thenReturn(1l);
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcl:org:dma/user/urn:mrn:mcl:user:dma:thc").with(authentication(auth))
                    .header("Origin", "bla")
            ).andExpect(status().isOk()).andExpect(content().json(userJson, false));
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
        verify(this.entityService, atLeastOnce()).getByMrn("urn:mrn:mcl:user:dma:thc");
    }

    /**
     * Try to get a user with the appropriate rights, but different org
     */
    @Test
    public void testAccessGetUserWithRights2() {
        // Build user object to test with
        User user = new User();
        user.setMrn("urn:mrn:mcl:user:dma:thc");
        user.setFirstName("Thomas");
        user.setLastName("Christensen");
        user.setIdOrganization(1l);
        user.setEmail("thcc@dma.dk");
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcl:org:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Create fake authentication token, note that the user mrn is different from the org mrn, but being SITE_ADMIN should overrule that
        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcl:org:sma", "ROLE_ORG_ADMIN,ROLE_SITE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcl:org:dma")).willReturn(org);
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcl:org:sma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcl:user:dma:thc")).willReturn(user);
        when(org.getId()).thenReturn(1l);
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcl:org:dma/user/urn:mrn:mcl:user:dma:thc").with(authentication(auth))
                    .header("Origin", "bla")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }


    /**
     * Try to update a user without the appropriate association
     */
    @Test
    public void testAccessUpdateUserWithoutRights() {
        // Build user object to test with
        User user = new User();
        user.setMrn("urn:mrn:mcl:user:dma:thc");
        user.setFirstName("Thomas");
        user.setLastName("Christensen");
        user.setEmail("thcc@dma.dk");
        user.setIdOrganization(1l);
        String userJson = serialize(user);
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcl:org:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Create fake authentication token
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcl:org:dma", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcl:org:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcl:user:dma:thc")).willReturn(user);
        when(org.getId()).thenReturn(1l);
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcl:org:dma/user/urn:mrn:mcl:user:dma:thc").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(userJson)
                    .contentType("application/json")
            ).andExpect(status().isForbidden());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Try to update a user with the appropriate association
     */
    @Test
    public void testAccessUpdateUserWithRights() {
        // Build user object to test with
        User user = new User();
        user.setMrn("urn:mrn:mcl:user:dma:thc");
        user.setFirstName("Thomas");
        user.setLastName("Christensen");
        user.setEmail("thcc@dma.dk");
        user.setIdOrganization(1l);
        user.setPermissions("MCADMIN");
        String userJson = serialize(user);
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcl:org:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        org.setFederationType("test-idp");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Create fake authentication token
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcl:org:dma", "ROLE_USER_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcl:org:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcl:user:dma:thc")).willReturn(user);
        when(org.getId()).thenReturn(1l);
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcl:org:dma/user/urn:mrn:mcl:user:dma:thc").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(userJson)
                    .contentType("application/json")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
        try {
            verify(this.keycloakAU, times(1)).updateUser("urn:mrn:mcl:user:dma:thc", "Thomas", "Christensen", "thcc@dma.dk", "MCADMIN", "");
        } catch (IOException e) {
            e.printStackTrace();
            fail();
        } catch (McBasicRestException e) {
            e.printStackTrace();
            fail();
        }
    }

    /**
     * Try to get a user with the appropriate association, but letter casing of orgMrn being different
     */
    @Test
    public void testAccessGetUserWithRightsOrgMrnDiffCase() {
        // Build user object to test with
        User user = new User();
        user.setMrn("urn:mrn:mcl:user:dma@dma:thc");
        user.setFirstName("Thomas");
        user.setLastName("Christensen");
        user.setIdOrganization(1l);
        user.setEmail("thcc@dma.dk");
        String userJson = serialize(user);
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcl:org:dma@dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Create fake authentication token
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcl:org:dma@dma", "ROLE_USER", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcl:org:dma@dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcl:user:DMA@dma:thc")).willReturn(user);
        when(org.getId()).thenReturn(1l);
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcl:org:dma@dma/user/urn:mrn:mcl:user:DMA@dma:thc").with(authentication(auth))
                    .header("Origin", "bla")
            ).andExpect(status().isOk()).andExpect(content().json(userJson, false));
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
        verify(this.entityService, atLeastOnce()).getByMrn("urn:mrn:mcl:user:DMA@dma:thc");
    }

    @Test
    public void testCreateUserForFederatedOrg() {
        // Build user object to test with
        User user = new User();
        user.setMrn("urn:mrn:mcl:user:dma:thc");
        user.setFirstName("Thomas");
        user.setLastName("Christensen");
        user.setEmail("thcc@dma.dk");
        user.setIdOrganization(1l);
        user.setPermissions("MCADMIN");
        String userJson = serialize(user);
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcl:org:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        org.setFederationType("external-idp");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Create fake authentication token
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcl:org:dma", "ROLE_USER_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcl:org:dma")).willReturn(org);
        when(org.getId()).thenReturn(1l);

        User newUser = new User();
        newUser.setMrn("urn:mrn:mcl:user");

        try {
            mvc.perform(post("/oidc/api/org/urn:mrn:mcl:org:dma/user").with(authentication(auth))
            .header("Origin", "Bla")
            .content(userJson)
            .contentType("application/json")).andExpect(status().is4xxClientError());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }

    }

    @Test
    public void testCreateUserForNonFederatedOrg() {
        // Build user object to test with
        User user = new User();
        user.setMrn("urn:mrn:mcl:user:dma:thc");
        user.setFirstName("Thomas");
        user.setLastName("Christensen");
        user.setEmail("thcc@dma.dk");
        user.setIdOrganization(1l);
        user.setPermissions("MCADMIN");
        String userJson = serialize(user);
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcl:org:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        org.setFederationType("test-idp");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Create fake authentication token
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcl:org:dma", "ROLE_USER_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcl:org:dma")).willReturn(org);
        when(org.getId()).thenReturn(1l);

        User newUser = new User();
        newUser.setMrn("urn:mrn:mcl:user");

        // setup mock SMTP server
        Wiser wiser = new Wiser(1025);
        wiser.start();

        try {
            mvc.perform(post("/oidc/api/org/urn:mrn:mcl:org:dma/user").with(authentication(auth))
                    .header("Origin", "Bla")
                    .content(userJson)
                    .contentType("application/json")).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            wiser.stop();
            assertTrue(false);
        }

        assertTrue(wiser.getMessages().size() > 0);
        wiser.stop();
    }

    @Test
    public void testUpdateUserFederatedOrg() {
        // Build user object to test with
        User user = new User();
        user.setMrn("urn:mrn:mcl:user:dma:thc");
        user.setFirstName("Thomas");
        user.setLastName("Christensen");
        user.setEmail("thcc@dma.dk");
        user.setIdOrganization(1l);
        user.setPermissions("MCADMIN");
        String userJson = serialize(user);
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcl:org:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        org.setFederationType("external-idp");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Create fake authentication token
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcl:org:dma", "ROLE_USER_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcl:org:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcl:user:dma:thc")).willReturn(user);
        when(org.getId()).thenReturn(1l);
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcl:org:dma/user/urn:mrn:mcl:user:dma:thc").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(userJson)
                    .contentType("application/json")
            ).andExpect(status().is4xxClientError());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Helper function to serialize a user to json
     * @param user
     * @return
     */
    private String serialize(User user) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            // Convert object to JSON string
            String jsonInString = mapper.writeValueAsString(user);
            //System.out.println(jsonInString);

            // Convert object to JSON string and pretty print
            jsonInString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(user);
            //System.out.println(jsonInString);

            return jsonInString;
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }
}
