/*
 * Copyright 2018 Danish Maritime Authority
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.maritimeconnectivity.identityregistry.controllers;

import net.maritimeconnectivity.identityregistry.model.database.Agent;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.services.AgentService;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@ContextConfiguration
@WebAppConfiguration
public class AgentControllerTests {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mvc;

    @MockBean
    private OrganizationService organizationService;

    @MockBean
    private AgentService agentService;

    @Before
    public void setup() {
        mvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    @Test
    public void testCreateAgentWithRights() {
        Organization actingOrg = mock(Organization.class);
        actingOrg.setMrn("urn:mrn:mcp:org:agent");
        Organization onBehalfOfOrg = mock(Organization.class);
        onBehalfOfOrg.setMrn("urn:mrn:mcp:org:dma");

        Agent agent = new Agent();
        agent.setIdActingOrganization(1L);
        agent.setIdOnBehalfOfOrganization(2L);

        String agentJson = JSONSerializer.serialize(agent);

        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:dma", "ROLE_ORG_ADMIN", "");

        given(this.organizationService.getOrganizationById(any())).willReturn(actingOrg);
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:dma")).willReturn(onBehalfOfOrg);
        given(onBehalfOfOrg.getId()).willReturn(2L);

        try {
            mvc.perform(post("/oidc/api/org/urn:mrn:mcp:org:dma/agent").with(authentication(auth))
                .header("Origin", "bla")
                .content(agentJson)
                .contentType("application/json")).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    @Test
    public void testCreateAgentWithoutRights() {
        Organization actingOrg = mock(Organization.class);
        actingOrg.setMrn("urn:mrn:mcp:org:agent");
        Organization onBehalfOfOrg = mock(Organization.class);
        onBehalfOfOrg.setMrn("urn:mrn:mcp:org:dma");

        Agent agent = new Agent();
        agent.setIdActingOrganization(1L);
        agent.setIdOnBehalfOfOrganization(2L);

        String agentJson = JSONSerializer.serialize(agent);

        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:agent", "ROLE_ORG_ADMIN", "");

        given(this.organizationService.getOrganizationById(any())).willReturn(actingOrg);
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:dma")).willReturn(onBehalfOfOrg);
        given(onBehalfOfOrg.getId()).willReturn(2L);

        try {
            mvc.perform(post("/oidc/api/org/urn:mrn:mcp:org:dma/agent").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(agentJson)
                    .contentType("application/json")).andExpect(status().isForbidden());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    @Test
    public void testGetAgentWithRights() {
        Agent agent = new Agent();
        agent.setIdOnBehalfOfOrganization(1L);
        agent.setIdActingOrganization(2L);

        Organization organization = mock(Organization.class);

        String agentJson = JSONSerializer.serialize(agent);

        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:dma")).willReturn(organization);
        given(this.agentService.getById(3L)).willReturn(agent);
        given(organization.getId()).willReturn(1L);
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:dma")).willReturn(organization);

        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:dma", "ROLE_USER", "");

        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:dma/agent/3").with(authentication(auth))
            .header("Origin", "bla")).andExpect(status().isOk()).andExpect(content().json(agentJson, false));
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    @Test
    public void testUpdateAgentWithRights() {
        Agent agent = new Agent();
        agent.setIdOnBehalfOfOrganization(1L);
        agent.setIdActingOrganization(2L);

        Organization organization = mock(Organization.class);

        String agentJson = JSONSerializer.serialize(agent);

        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:dma")).willReturn(organization);
        given(this.agentService.getById(3L)).willReturn(agent);
        given(organization.getId()).willReturn(1L);

        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:dma", "ROLE_ORG_ADMIN", "");

        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:dma/agent/3").with(authentication(auth))
                    .header("Origin", "bla").contentType("application/json").content(agentJson))
                    .andExpect(status().isOk()).andExpect(content().json(agentJson, false));
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    @Test
    public void testUpdateAgentWithoutRights() {
        Agent agent = new Agent();
        agent.setIdOnBehalfOfOrganization(1L);
        agent.setIdActingOrganization(2L);

        Organization organization = mock(Organization.class);

        String agentJson = JSONSerializer.serialize(agent);

        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:dma")).willReturn(organization);
        given(this.agentService.getById(3L)).willReturn(agent);
        given(organization.getId()).willReturn(1L);

        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:dma", "ROLE_USER", "");

        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:dma/agent/3").with(authentication(auth))
                    .header("Origin", "bla").contentType("application/json").content(agentJson))
                    .andExpect(status().isForbidden());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    @Test
    public void testDeleteAgentWithRights() {
        Agent agent = new Agent();
        agent.setIdOnBehalfOfOrganization(1L);
        agent.setIdActingOrganization(2L);

        Organization organization = mock(Organization.class);

        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:dma")).willReturn(organization);
        given(this.agentService.getById(3L)).willReturn(agent);
        given(organization.getId()).willReturn(1L);

        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:dma", "ROLE_ORG_ADMIN", "");

        try {
            mvc.perform(delete("/oidc/api/org/urn:mrn:mcp:org:dma/agent/3")
                    .with(authentication(auth))
                    .header("Origin", "bla")).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    @Test
    public void testDeleteAgentWithoutRights() {
        Agent agent = new Agent();
        agent.setIdOnBehalfOfOrganization(1L);
        agent.setIdActingOrganization(2L);

        Organization organization = mock(Organization.class);

        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:dma")).willReturn(organization);
        given(this.agentService.getById(3L)).willReturn(agent);
        given(organization.getId()).willReturn(1L);

        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:dma", "ROLE_USER", "");

        try {
            mvc.perform(delete("/oidc/api/org/urn:mrn:mcp:org:dma/agent/3")
                    .with(authentication(auth))
                    .header("Origin", "bla")).andExpect(status().isForbidden());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }
}
