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

package net.maritimeconnectivity.identityregistry.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.maritimeconnectivity.identityregistry.model.database.IdentityProviderAttribute;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.model.database.entities.MMS;
import net.maritimeconnectivity.identityregistry.services.EntityService;
import net.maritimeconnectivity.identityregistry.services.MMSService;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
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

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertTrue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.spy;
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
public class MMSControllerTests {
    @Autowired
    private WebApplicationContext context;

    private MockMvc mvc;
    @MockBean(value = {MMSService.class})
    private EntityService<MMS> entityService;

    @MockBean
    private OrganizationService organizationService;

    @Before
    public void setup() {
        mvc = MockMvcBuilders
                .webAppContextSetup(context)
                //.alwaysDo(print())
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    /**
     * Try to get a mms without being authenticated
     */
    @WithMockUser()
    @Test
    public void testAccessGetMMSWithoutRights() {
        given(this.entityService.getByMrn("urn:mrn:mcp:mms:idp1:dma:test1")).willReturn(new MMS());
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:dma/mms/urn:mrn:mcp:mms:idp1:dma:test1").header("Origin", "bla")).andExpect(status().isForbidden());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Try to get a mms with the appropriate association
     */
    @Test
    public void testAccessGetMMSWithRights() {
        // Build service object to test with
        MMS mms = new MMS();
        mms.setMrn("urn:mrn:mcp:mms:idp1:dma:test1");
        mms.setMrnSubsidiary("urn:mrn:mcp:mms:dma:test1");
        mms.setName("MMS test instance 1");
        mms.setUrl("https://maritimeconnectivity.net/");
        mms.setIdOrganization(1l);
        String mmsJson = serialize(mms);
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
        given(this.entityService.getByMrn("urn:mrn:mcp:mms:idp1:dma:test1")).willReturn(mms);
        when(org.getId()).thenReturn(1l);
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/mms/urn:mrn:mcp:mms:idp1:dma:test1").with(authentication(auth))
                    .header("Origin", "bla")
            ).andExpect(status().isOk()).andExpect(content().json(mmsJson, false));
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
        verify(((MMSService) this.entityService), atLeastOnce()).getByMrn("urn:mrn:mcp:mms:idp1:dma:test1");
    }

    /**
     * Try to get a mms with the appropriate rights, but different org
     */
    @Test
    public void testAccessGetMMSWithRights2() {
        // Build service object to test with
        MMS mms = new MMS();
        mms.setMrn("urn:mrn:mcp:mms:idp1:dma:test1");
        mms.setMrnSubsidiary("urn:mrn:mcp:mms:dma:test1");
        mms.setName("MMS test instance 1");
        mms.setUrl("https://maritimeconnectivity.net/");
        mms.setIdOrganization(1l);
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
        given(((MMSService) this.entityService).getByMrn("urn:mrn:mcp:mms:idp1:dma:test1")).willReturn(mms);
        when(org.getId()).thenReturn(1l);
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/mms/urn:mrn:mcp:mms:idp1:dma:test1").with(authentication(auth))
                    .header("Origin", "bla")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Try to update a mms with the appropriate association
     */
    @Test
    public void testAccessUpdateMMSWithRights() {
        // Build service object to test with
        MMS mms = new MMS();
        mms.setMrn("urn:mrn:mcp:mms:idp1:dma:test1");
        mms.setMrnSubsidiary("urn:mrn:mcp:mms:idp1:dma:test1");
        mms.setName("MMS test instance 1");
        mms.setUrl("https://maritimeconnectivity.net/");
        mms.setIdOrganization(1l);
        String mmsJson = serialize(mms);
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
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:idp1:dma", "ROLE_MMS_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcp:mms:idp1:dma:test1")).willReturn(mms);
        when(org.getId()).thenReturn(1l);
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/mms/urn:mrn:mcp:mms:idp1:dma:test1").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(mmsJson)
                    .contentType("application/json")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Try to update a mms without the appropriate association
     */
    @Test
    public void testAccessUpdateMMSWithoutRights() {
        // Build service object to test with
        MMS mms = new MMS();
        mms.setMrn("urn:mrn:mcp:mms:idp1:dma:test1");
        mms.setMrnSubsidiary("urn:mrn:mcp:mms:dma:test1");
        mms.setName("MMS test instance 1");
        mms.setUrl("https://maritimeconnectivity.net/");
        mms.setIdOrganization(1l);
        String mmsJson = serialize(mms);
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
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:idp1:dma", "ROLE_USER_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcp:mms:idp1:dma:test1")).willReturn(mms);
        when(org.getId()).thenReturn(1l);
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/mms/urn:mrn:mcp:mms:idp1:dma:test1").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(mmsJson)
                    .contentType("application/json")
            ).andExpect(status().isForbidden());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Try to update a service with the appropriate association but with version set to null
     */
    @Test
    public void testCreateMMSWithUrlNull() {
        // Build service object to test with
        MMS mms = new MMS();
        mms.setMrn("urn:mrn:mcp:mms:idp1:dma:test1");
        mms.setMrnSubsidiary("urn:mrn:mcp:mms:idp1:dma:test1");
        mms.setName("MMS test instance 1");
        mms.setUrl(null);
        mms.setIdOrganization(1l);
        String mmsJson = serialize(mms);
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
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:idp1:dma", "ROLE_MMS_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        when(org.getId()).thenReturn(1l);
        try {
            mvc.perform(post("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/mms").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(mmsJson)
                    .contentType("application/json")
            ).andExpect(status().isBadRequest());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Try to update a mms with a null subsidiary mrn
     */
    @Test
    public void testUpdateMMS() {
        // Build service object to test with
        MMS mms = new MMS();
        mms.setMrn("urn:mrn:mcp:mms:idp1:dma:test1");
        mms.setMrnSubsidiary("urn:mrn:mcp:mms:idp1:dma:test1");
        mms.setName("MMS test instance 1");
        mms.setUrl("https://maritimeconnectivity.net/");
        mms.setIdOrganization(1l);
        String mmsJson = serialize(mms);
        // Old service that we want to update
        MMS existingMms = new MMS();
        existingMms.setMrn("urn:mrn:mcp:mms:idp1:dma:test1");
        existingMms.setMrnSubsidiary(null);
        existingMms.setName("MMS test instance 1");
        existingMms.setUrl("https://maritimeconnectivity.net/");
        existingMms.setIdOrganization(1l);
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
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:idp1:dma", "ROLE_MMS_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(((MMSService) this.entityService).getByMrn("urn:mrn:mcp:mms:idp1:dma:test1")).willReturn(existingMms);
        when(org.getId()).thenReturn(1l);
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/mms/urn:mrn:mcp:mms:idp1:dma:test1").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(mmsJson)
                    .contentType("application/json")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }


    /**
     * Helper function to serialize a mms to json
     * @param mms
     * @return
     */
    private String serialize(MMS mms) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            // Convert object to JSON string
            String jsonInString = mapper.writeValueAsString(mms);
            //System.out.println(jsonInString);

            // Convert object to JSON string and pretty print
            jsonInString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(mms);
            //System.out.println(jsonInString);

            return jsonInString;
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }
}
