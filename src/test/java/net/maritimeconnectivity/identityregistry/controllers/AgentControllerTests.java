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
import net.maritimeconnectivity.identityregistry.model.database.TimestampModel;
import net.maritimeconnectivity.identityregistry.services.AgentService;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.fail;
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

@ExtendWith(SpringExtension.class)
@SpringBootTest
@ContextConfiguration
@WebAppConfiguration
class AgentControllerTests {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mvc;

    @MockBean
    private OrganizationService organizationService;

    @MockBean
    private AgentService agentService;

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    @Test
    void testCreateAgentWithRights() throws NoSuchFieldException, IllegalAccessException {
        Organization actingOrg = mock(Organization.class);
        actingOrg.setMrn("urn:mrn:mcp:org:idp1:agent");
        Organization onBehalfOfOrg = mock(Organization.class);
        onBehalfOfOrg.setMrn("urn:mrn:mcp:org:idp1:dma");

        Agent agent = new Agent();
        agent.setIdActingOrganization(1L);
        agent.setIdOnBehalfOfOrganization(2L);

        // We need to use reflection to set the id of the agent as the "id" field does not have a setter
        Field idField = TimestampModel.class.getDeclaredField("id");
        idField.setAccessible(true);
        idField.set(agent, 10L);

        String agentJson = JSONSerializer.serialize(agent);

        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "ROLE_ORG_ADMIN", "");

        given(this.organizationService.getOrganizationById(any())).willReturn(actingOrg);
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(onBehalfOfOrg);
        given(this.agentService.save(any())).willReturn(agent);
        given(onBehalfOfOrg.getId()).willReturn(2L);

        try {
            mvc.perform(post("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/agent").with(authentication(auth))
                .header("Origin", "bla")
                .content(agentJson)
                .contentType("application/json")).andExpect(status().isCreated());
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testCreateAgentWithoutRights() {
        Organization actingOrg = mock(Organization.class);
        actingOrg.setMrn("urn:mrn:mcp:org:idp1:agent");
        Organization onBehalfOfOrg = mock(Organization.class);
        onBehalfOfOrg.setMrn("urn:mrn:mcp:org:idp1:dma");

        Agent agent = new Agent();
        agent.setIdActingOrganization(1L);
        agent.setIdOnBehalfOfOrganization(2L);

        String agentJson = JSONSerializer.serialize(agent);

        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:agent:user", "ROLE_ORG_ADMIN", "");

        given(this.organizationService.getOrganizationById(any())).willReturn(actingOrg);
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(onBehalfOfOrg);
        given(onBehalfOfOrg.getId()).willReturn(2L);

        try {
            mvc.perform(post("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/agent").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(agentJson)
                    .contentType("application/json")).andExpect(status().isForbidden());
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testGetAgentWithRights() {
        Agent agent = new Agent();
        agent.setIdOnBehalfOfOrganization(1L);
        agent.setIdActingOrganization(2L);

        Organization organization = mock(Organization.class);

        String agentJson = JSONSerializer.serialize(agent);

        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(organization);
        given(this.agentService.getById(3L)).willReturn(agent);
        given(organization.getId()).willReturn(1L);
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(organization);

        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "ROLE_USER", "");

        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/agent/3").with(authentication(auth))
            .header("Origin", "bla")).andExpect(status().isOk()).andExpect(content().json(agentJson, false));
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testUpdateAgentWithRights() {
        Agent agent = new Agent();
        agent.setIdOnBehalfOfOrganization(1L);
        agent.setIdActingOrganization(2L);

        Organization organization = mock(Organization.class);

        String agentJson = JSONSerializer.serialize(agent);

        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(organization);
        given(this.agentService.getById(3L)).willReturn(agent);
        given(organization.getId()).willReturn(1L);

        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "ROLE_ORG_ADMIN", "");

        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/agent/3").with(authentication(auth))
                    .header("Origin", "bla").contentType("application/json").content(agentJson))
                    .andExpect(status().isOk()).andExpect(content().json(agentJson, false));
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testUpdateAgentWithoutRights() {
        Agent agent = new Agent();
        agent.setIdOnBehalfOfOrganization(1L);
        agent.setIdActingOrganization(2L);

        Organization organization = mock(Organization.class);

        String agentJson = JSONSerializer.serialize(agent);

        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(organization);
        given(this.agentService.getById(3L)).willReturn(agent);
        given(organization.getId()).willReturn(1L);

        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "ROLE_USER", "");

        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/agent/3").with(authentication(auth))
                    .header("Origin", "bla").contentType("application/json").content(agentJson))
                    .andExpect(status().isForbidden());
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testDeleteAgentWithRights() {
        Agent agent = new Agent();
        agent.setIdOnBehalfOfOrganization(1L);
        agent.setIdActingOrganization(2L);

        Organization organization = mock(Organization.class);

        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(organization);
        given(this.agentService.getById(3L)).willReturn(agent);
        given(organization.getId()).willReturn(1L);

        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "ROLE_ORG_ADMIN", "");

        try {
            mvc.perform(delete("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/agent/3")
                    .with(authentication(auth))
                    .header("Origin", "bla")).andExpect(status().isOk());
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testDeleteAgentWithoutRights() {
        Agent agent = new Agent();
        agent.setIdOnBehalfOfOrganization(1L);
        agent.setIdActingOrganization(2L);

        Organization organization = mock(Organization.class);

        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(organization);
        given(this.agentService.getById(3L)).willReturn(agent);
        given(organization.getId()).willReturn(1L);

        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "ROLE_USER", "");

        try {
            mvc.perform(delete("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/agent/3")
                    .with(authentication(auth))
                    .header("Origin", "bla")).andExpect(status().isForbidden());
        } catch (Exception e) {
            fail(e);
        }
    }
}
