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

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.Setter;
import net.maritimeconnectivity.identityregistry.exception.McBasicRestException;
import net.maritimeconnectivity.identityregistry.model.data.ExceptionModel;
import net.maritimeconnectivity.identityregistry.model.database.IdentityProviderAttribute;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.model.database.entities.User;
import net.maritimeconnectivity.identityregistry.services.CertificateService;
import net.maritimeconnectivity.identityregistry.services.EntityService;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import net.maritimeconnectivity.identityregistry.utils.KeycloakAdminUtil;
import net.maritimeconnectivity.identityregistry.utils.MCIdRegConstants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.subethamail.wiser.Wiser;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
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

@ExtendWith(SpringExtension.class)
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

    @Getter
    @Setter
    @Value("${spring.mail.port}")
    private int smtpServerPort;

    @BeforeEach
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
        given(this.entityService.getByMrn("urn:mrn:mcp:user:idp1:dma:thc")).willReturn(new User());
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/user/urn:mrn:mcp:user:idp1:dma:thc").header("Origin", "bla")).andExpect(status().isForbidden());
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
        user.setMrn("urn:mrn:mcp:user:idp1:dma:thc");
        user.setFirstName("Thomas");
        user.setLastName("Christensen");
        user.setIdOrganization(1L);
        user.setEmail("thcc@dma.dk");
        String userJson = serialize(user);
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Create fake authentication token
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:idp1:dma", "ROLE_USER", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcp:user:idp1:dma:thc")).willReturn(user);
        when(org.getId()).thenReturn(1L);
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/user/urn:mrn:mcp:user:idp1:dma:thc").with(authentication(auth))
                    .header("Origin", "bla")
            ).andExpect(status().isOk()).andExpect(content().json(userJson, false));
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
        verify(this.entityService, atLeastOnce()).getByMrn("urn:mrn:mcp:user:idp1:dma:thc");
    }

    /**
     * Try to get a user with the appropriate rights, but different org
     */
    @Test
    public void testAccessGetUserWithRights2() {
        // Build user object to test with
        User user = new User();
        user.setMrn("urn:mrn:mcp:user:idp1:dma:thc");
        user.setFirstName("Thomas");
        user.setLastName("Christensen");
        user.setIdOrganization(1L);
        user.setEmail("thcc@dma.dk");
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Create fake authentication token, note that the user mrn is different from the org mrn, but being SITE_ADMIN should overrule that
        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:idp1:sma", "ROLE_ORG_ADMIN,ROLE_SITE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:sma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcp:user:idp1:dma:thc")).willReturn(user);
        when(org.getId()).thenReturn(1L);
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/user/urn:mrn:mcp:user:idp1:dma:thc").with(authentication(auth))
                    .header("Origin", "bla")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }


    /**
     * Try to update a user without the appropriate association
     */
    @Test
    public void testAccessUpdateUserWithoutRights() {
        // Build user object to test with
        User user = new User();
        user.setMrn("urn:mrn:mcp:user:idp1:dma:thc");
        user.setFirstName("Thomas");
        user.setLastName("Christensen");
        user.setEmail("thcc@dma.dk");
        user.setIdOrganization(1L);
        String userJson = serialize(user);
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Create fake authentication token
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:idp1:dma", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcp:user:idp1:dma:thc")).willReturn(user);
        when(org.getId()).thenReturn(1L);
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/user/urn:mrn:mcp:user:idp1:dma:thc").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(userJson)
                    .contentType("application/json")
            ).andExpect(status().isForbidden());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }

    /**
     * Try to update a user with the appropriate association
     */
    @Test
    public void testAccessUpdateUserWithRights() {
        // Build user object to test with
        User user = new User();
        user.setMrn("urn:mrn:mcp:user:idp1:dma:thc");
        user.setFirstName("Thomas");
        user.setLastName("Christensen");
        user.setEmail("thcc@dma.dk");
        user.setIdOrganization(1L);
        user.setPermissions("MCADMIN");
        String userJson = serialize(user);
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        org.setFederationType("test-idp");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Create fake authentication token
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:idp1:dma", "ROLE_USER_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcp:user:idp1:dma:thc")).willReturn(user);
        when(org.getId()).thenReturn(1L);
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/user/urn:mrn:mcp:user:idp1:dma:thc").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(userJson)
                    .contentType("application/json")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
        try {
            verify(this.keycloakAU, times(1)).updateUser("urn:mrn:mcp:user:idp1:dma:thc", "Thomas", "Christensen", "thcc@dma.dk", "MCADMIN", "");
        } catch (IOException | McBasicRestException e) {
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
        user.setMrn("urn:mrn:mcp:user:idp1:dma@dma:thc");
        user.setFirstName("Thomas");
        user.setLastName("Christensen");
        user.setIdOrganization(1L);
        user.setEmail("thcc@dma.dk");
        String userJson = serialize(user);
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcp:org:idp1:dma@dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Create fake authentication token
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:idp1:dma@dma", "ROLE_USER", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma@dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcp:user:idp1:DMA@dma:thc")).willReturn(user);
        when(org.getId()).thenReturn(1L);
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:idp1:dma@dma/user/urn:mrn:mcp:user:idp1:DMA@dma:thc").with(authentication(auth))
                    .header("Origin", "bla")
            ).andExpect(status().isOk()).andExpect(content().json(userJson, false));
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
        verify(this.entityService, atLeastOnce()).getByMrn("urn:mrn:mcp:user:idp1:DMA@dma:thc");
    }

    @Test
    public void testCreateUserForFederatedOrg() {
        // Build user object to test with
        User user = new User();
        user.setMrn("urn:mrn:mcp:user:idp1:dma:thc");
        user.setFirstName("Thomas");
        user.setLastName("Christensen");
        user.setEmail("thcc@dma.dk");
        user.setIdOrganization(1L);
        user.setPermissions("MCADMIN");
        String userJson = serialize(user);
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        org.setFederationType("external-idp");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Create fake authentication token
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:idp1:dma", "ROLE_USER_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        when(org.getId()).thenReturn(1L);

        User newUser = new User();
        newUser.setMrn("urn:mrn:mcp:user:idp1:dma:user1");

        try {
            mvc.perform(post("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/user").with(authentication(auth))
            .header("Origin", "Bla")
            .content(userJson)
            .contentType("application/json")).andExpect(status().is4xxClientError());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }

    }

    @Test
    public void testCreateUserForNonFederatedOrg() {
        // Build user object to test with
        User user = new User();
        user.setMrn("urn:mrn:mcp:user:idp1:dma:thc");
        user.setFirstName("Thomas");
        user.setLastName("Christensen");
        user.setEmail("thcc@dma.dk");
        user.setIdOrganization(1L);
        user.setPermissions("MCADMIN");
        String userJson = serialize(user);
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        org.setFederationType("test-idp");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Create fake authentication token
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:idp1:dma", "ROLE_USER_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        when(org.getId()).thenReturn(1L);

        User newUser = new User();
        newUser.setMrn("urn:mrn:mcp:user:idp1:dma:user1");

        // setup mock SMTP server
        Wiser wiser = new Wiser(smtpServerPort);
        wiser.start();

        try {
            mvc.perform(post("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/user").with(authentication(auth))
                    .header("Origin", "Bla")
                    .content(userJson)
                    .contentType("application/json")).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            wiser.stop();
            fail();
        }

        assertTrue(wiser.getMessages().size() > 0);
        wiser.stop();
    }

    @Test
    public void testUpdateUserFederatedOrg() {
        // Build user object to test with
        User user = new User();
        user.setMrn("urn:mrn:mcp:user:idp1:dma:thc");
        user.setFirstName("Thomas");
        user.setLastName("Christensen");
        user.setEmail("thcc@dma.dk");
        user.setIdOrganization(1L);
        user.setPermissions("MCADMIN");
        String userJson = serialize(user);
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        org.setFederationType("external-idp");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Create fake authentication token
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:idp1:dma", "ROLE_USER_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcp:user:idp1:dma:thc")).willReturn(user);
        when(org.getId()).thenReturn(1L);
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/user/urn:mrn:mcp:user:idp1:dma:thc").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(userJson)
                    .contentType("application/json")
            ).andExpect(status().is4xxClientError());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }

    @Test
    public void testIssueCertificateUsingCsr() {
        // Build user object to test with
        User user = new User();
        user.setMrn("urn:mrn:mcp:user:idp1:dma:thc");
        user.setFirstName("Thomas");
        user.setLastName("Christensen");
        user.setEmail("thcc@dma.dk");
        user.setIdOrganization(1L);
        user.setPermissions("MCADMIN");
        String userJson = serialize(user);
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        org.setFederationType("external-idp");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        org.setCertificateAuthority("urn:mrn:mcp:ca:idp1:mcp-idreg");
        // Create fake authentication token
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:idp1:dma", "ROLE_USER_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcp:user:idp1:dma:thc")).willReturn(user);
        when(org.getId()).thenReturn(1L);

        try {
            String csr = new String(Files.readAllBytes(new File("src/test/resources/ecCsr.csr").toPath()));
            MvcResult result = mvc.perform(post("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/user/urn:mrn:mcp:user:idp1:dma:thc/certificate/issue-new/csr").with(authentication(auth))
                    .header("Origin", "bla")
                    .contentType(MediaType.TEXT_PLAIN)
                    .content(csr)
            ).andExpect(status().isOk()).andReturn();
            String content = result.getResponse().getContentAsString();
            assertNotNull(content);
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }

    @Test
    public void testIssueCertificateUsingCsrWithWeakRSAKey() {
        // Build user object to test with
        User user = new User();
        user.setMrn("urn:mrn:mcp:user:idp1:dma:thc");
        user.setFirstName("Thomas");
        user.setLastName("Christensen");
        user.setEmail("thcc@dma.dk");
        user.setIdOrganization(1L);
        user.setPermissions("MCADMIN");
        String userJson = serialize(user);
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        org.setFederationType("external-idp");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        org.setCertificateAuthority("urn:mrn:mcp:ca:idp1:mcp-idreg");
        // Create fake authentication token
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:idp1:dma", "ROLE_USER_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcp:user:idp1:dma:thc")).willReturn(user);
        when(org.getId()).thenReturn(1L);

        try {
            String csr = new String(Files.readAllBytes(new File("src/test/resources/WeakRSA.csr").toPath()));
            MvcResult result = mvc.perform(post("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/user/urn:mrn:mcp:user:idp1:dma:thc/certificate/issue-new/csr").with(authentication(auth))
                    .header("Origin", "bla")
                    .contentType(MediaType.TEXT_PLAIN)
                    .content(csr)
            ).andExpect(status().is4xxClientError()).andReturn();
            String content = result.getResponse().getContentAsString();
            ExceptionModel exceptionModel = deserializeError(content);
            assertEquals("Message is not as expected", MCIdRegConstants.RSA_KEY_TOO_SHORT, exceptionModel.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }

    @Test
    public void testIssueCertificateUsingCsrWithWeakECKey() {
        // Build user object to test with
        User user = new User();
        user.setMrn("urn:mrn:mcp:user:idp1:dma:thc");
        user.setFirstName("Thomas");
        user.setLastName("Christensen");
        user.setEmail("thcc@dma.dk");
        user.setIdOrganization(1L);
        user.setPermissions("MCADMIN");
        String userJson = serialize(user);
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        org.setFederationType("external-idp");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        org.setCertificateAuthority("urn:mrn:mcp:ca:idp1:mcp-idreg");
        // Create fake authentication token
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:idp1:dma", "ROLE_USER_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcp:user:idp1:dma:thc")).willReturn(user);
        when(org.getId()).thenReturn(1L);

        try {
            String csr = new String(Files.readAllBytes(new File("src/test/resources/WeakEC.csr").toPath()));
            MvcResult result = mvc.perform(post("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/user/urn:mrn:mcp:user:idp1:dma:thc/certificate/issue-new/csr").with(authentication(auth))
                    .header("Origin", "bla")
                    .contentType(MediaType.TEXT_PLAIN)
                    .content(csr)
            ).andExpect(status().is4xxClientError()).andReturn();
            String content = result.getResponse().getContentAsString();
            ExceptionModel exceptionModel = deserializeError(content);
            assertEquals("Message is not as expected", MCIdRegConstants.EC_KEY_TOO_SHORT, exceptionModel.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }

    @Test
    public void testIssueCertificateUsingCsrWithWeakSignature() {
        // Build user object to test with
        User user = new User();
        user.setMrn("urn:mrn:mcp:user:idp1:dma:thc");
        user.setFirstName("Thomas");
        user.setLastName("Christensen");
        user.setEmail("thcc@dma.dk");
        user.setIdOrganization(1L);
        user.setPermissions("MCADMIN");
        String userJson = serialize(user);
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        org.setFederationType("external-idp");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        org.setCertificateAuthority("urn:mrn:mcp:ca:idp1:mcp-idreg");
        // Create fake authentication token
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:idp1:dma", "ROLE_USER_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcp:user:idp1:dma:thc")).willReturn(user);
        when(org.getId()).thenReturn(1L);

        try {
            String csr = new String(Files.readAllBytes(new File("src/test/resources/RSAWeakSig.csr").toPath()));
            MvcResult result = mvc.perform(post("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/user/urn:mrn:mcp:user:idp1:dma:thc/certificate/issue-new/csr").with(authentication(auth))
                    .header("Origin", "bla")
                    .contentType(MediaType.TEXT_PLAIN)
                    .content(csr)
            ).andExpect(status().is4xxClientError()).andReturn();
            String content = result.getResponse().getContentAsString();
            ExceptionModel exceptionModel = deserializeError(content);
            assertEquals("Message is not as expected", MCIdRegConstants.WEAK_HASH, exceptionModel.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
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

    private ExceptionModel deserializeError(String content) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.readValue(content, ExceptionModel.class);
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }
}
