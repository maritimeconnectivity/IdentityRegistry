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
import net.maritimeconnectivity.identityregistry.model.database.Agent;
import net.maritimeconnectivity.identityregistry.model.database.IdentityProviderAttribute;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.model.database.entities.Device;
import net.maritimeconnectivity.identityregistry.model.database.entities.Service;
import net.maritimeconnectivity.identityregistry.model.database.entities.User;
import net.maritimeconnectivity.identityregistry.services.AgentService;
import net.maritimeconnectivity.identityregistry.services.CertificateService;
import net.maritimeconnectivity.identityregistry.services.EntityService;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import net.maritimeconnectivity.identityregistry.services.RoleService;
import net.maritimeconnectivity.identityregistry.utils.EmailUtil;
import net.maritimeconnectivity.identityregistry.utils.KeycloakAdminUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@WebAppConfiguration
public class OrganizationControllerTests {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mvc;

    @MockBean
    private EntityService<Device> deviceService;
    @MockBean
    private EntityService<Service> serviceService;
    @MockBean
    private EntityService<User> userService;

    @MockBean
    private RoleService roleService;

    @MockBean
    private EmailUtil emailUtil;

    @MockBean
    private OrganizationService organizationService;

    @MockBean
    private KeycloakAdminUtil keycloakAU;

    @MockBean
    private CertificateService certificateService;

    @MockBean
    private AgentService agentService;

    @BeforeEach
    public void setup() {
        mvc = MockMvcBuilders
                .webAppContextSetup(context)
                //.alwaysDo(print())
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
        MockitoAnnotations.openMocks(this);
    }

    /**
     * Try to apply for an organization to be created
     */
    @Test
    public void testApply() {
        // Build org object to test with
        Organization org = new Organization();
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Serialize org object
        String orgJson = this.serialize(org);
        given(this.organizationService.save(any())).willReturn(org);
        try {
            mvc.perform(post("/oidc/api/org/apply")
                    .header("Origin", "bla")
                    .content(orgJson)
                    .contentType("application/json")
            ).andExpect(status().isCreated());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }


    /**
     * Try to approve an organization without the appropriate role
     */
    @WithMockUser(roles="ORG_ADMIN")
    @Test
    public void testAccessApproveOrgWithoutRights() {
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/approve").header("Origin", "bla")).andExpect(status().isForbidden());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }

    /**
     * Try to approve an organization with the appropriate role
     */
    @WithMockUser(roles="SITE_ADMIN")
    @Test
    public void testAccessApproveOrgWithRights() {
        given(this.organizationService.getOrganizationByMrnDisregardApproved("urn:mrn:mcp:org:idp1:dma")).willReturn(new Organization());
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/approve").header("Origin", "bla")).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }

    /**
     * Try to delete an organization without the appropriate role
     */
    @WithMockUser(roles="ORG_ADMIN")
    @Test
    public void testAccessDeleteOrgWithoutRights() {
        try {
            mvc.perform(delete("/oidc/api/org/urn:mrn:mcp:org:idp1:dma").header("Origin", "bla")).andExpect(status().isForbidden());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }

    /**
     * Try to delete an organization with the appropriate role
     */
    @WithMockUser(roles="SITE_ADMIN")
    @Test
    public void testAccessDeleteOrgWithRights() {
        given(this.organizationService.getOrganizationByMrnDisregardApproved("urn:mrn:mcp:org:idp1:dma")).willReturn(new Organization());
        try {
            mvc.perform(delete("/oidc/api/org/urn:mrn:mcp:org:idp1:dma").header("Origin", "bla")).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }

    /**
     * Try to update an organization with the appropriate role
     */
    @Test
    public void testAccessUpdateOrgWithRights() {
        // Build org object to test with
        Organization org = new Organization();
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Serialize org object
        String orgJson = this.serialize(org);
        // Create fake authentication object
        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "ROLE_ORG_ADMIN", "");
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma").with(authentication(auth))
                            .header("Origin", "bla")
                            .content(orgJson)
                            .contentType("application/json")
                        ).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }

    @Test
    public void testAccessUpdateOrgAsAgent() {
        // Build org object to test with
        Organization org = new Organization();
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Serialize org object
        String orgJson = this.serialize(org);

        // Build the agent org object
        Organization agentOrg = new Organization();
        agentOrg.setMrn("urn:mrn:mcp:org:idp1:agent");
        agentOrg.setAddress("Agent Street 21");
        agentOrg.setCountry("Agent Country");
        agentOrg.setUrl("http://agent.org");
        agentOrg.setEmail("agent@agent.org");
        org.setName("The Agent Organization");
        agentOrg.setIdentityProviderAttributes(identityProviderAttributes);

        // Create agent object
        Agent agent = new Agent();
        agent.setIdOnBehalfOfOrganization(1L);
        agent.setIdActingOrganization(2L);
        // Create fake authentication object
        Authentication auth = TokenGenerator.generatePreAuthenticatedAuthenticationToken("urn:mrn:mcp:org:idp1:agent", "ROLE_ORG_ADMIN", "");
        Organization mock1 = mock(Organization.class);
        given(this.organizationService.getOrganizationByMrnNoFilter("urn:mrn:mcp:org:idp1:dma")).willReturn(mock1);
        Organization mock2 = mock(Organization.class);
        given(this.organizationService.getOrganizationByMrnNoFilter("urn:mrn:mcp:org:idp1:agent")).willReturn(mock2);
        List<Agent> agentList = (List<Agent>) mock(List.class);
        given(this.agentService.getAgentsByIdOnBehalfOfOrgAndIdActingOrg(mock1.getId(), mock2.getId())).willReturn(agentList);
        given(agentList.isEmpty()).willReturn(false);
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma").with(authentication(auth))
                .header("Origin", "bla")
                .content(orgJson)
                .contentType("application/json")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }

    @Test
    public void testAccessUpdateOrgAsAgentWithoutRights() {
        // Build org object to test with
        Organization org = new Organization();
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Serialize org object
        String orgJson = this.serialize(org);

        // Build the agent org object
        Organization agentOrg = new Organization();
        agentOrg.setMrn("urn:mrn:mcp:org:idp1:agent");
        agentOrg.setAddress("Agent Street 21");
        agentOrg.setCountry("Agent Country");
        agentOrg.setUrl("http://agent.org");
        agentOrg.setEmail("agent@agent.org");
        org.setName("The Agent Organization");
        agentOrg.setIdentityProviderAttributes(identityProviderAttributes);

        // Create agent object
        Agent agent = new Agent();
        agent.setIdOnBehalfOfOrganization(1L);
        agent.setIdActingOrganization(2L);
        // Create fake authentication object
        Authentication auth = TokenGenerator.generatePreAuthenticatedAuthenticationToken("urn:mrn:mcp:org:idp1:agent", "ROLE_USER", "");
        Organization mock1 = mock(Organization.class);
        given(this.organizationService.getOrganizationByMrnNoFilter("urn:mrn:mcp:org:idp1:dma")).willReturn(mock1);
        Organization mock2 = mock(Organization.class);
        given(this.organizationService.getOrganizationByMrnNoFilter("urn:mrn:mcp:org:idp1:agent")).willReturn(mock2);
        List<Agent> agentList = (List<Agent>) mock(List.class);
        given(this.agentService.getAgentsByIdOnBehalfOfOrgAndIdActingOrg(mock1.getId(), mock2.getId())).willReturn(agentList);
        given(agentList.isEmpty()).willReturn(false);
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(orgJson)
                    .contentType("application/json")
            ).andExpect(status().isForbidden());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }

    /**
     * Try to update an organization with data mismatch between json and url
     */
    @Test
    public void testAccessUpdateOrgWithDataMismatch() {
        // Build org object to test with
        Organization org = new Organization();
        // The mrn is deliberately wrong - that is the point of the test
        org.setMrn("urn:mrn:mcp:org:idp1:sma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Serialize org object
        String orgJson = this.serialize(org);
        // Create fake authentication object
        Authentication auth = TokenGenerator.generatePreAuthenticatedAuthenticationToken("urn:mrn:mcp:org:idp1:dma", "ROLE_ORG_ADMIN", "");
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        try {
            // Note that the mrn in the url is different from the org mrn - should mean it fails
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(orgJson)
                    .contentType("application/json")
            ).andExpect(status().isBadRequest());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }

    /**
     * Try to update an organization without the appropriate association
     */
    @Test
    public void testAccessUpdateOrgWithoutRights() {
        // Build org object to test with
        Organization org = new Organization();
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Serialize org object
        String orgJson = this.serialize(org);
        // Create fake authentication object - note that the users orgMrn is different from mrn of the org - means it should fail
        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:idp1:sma", "ROLE_ORG_ADMIN", "");
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(orgJson)
                    .contentType("application/json")
            ).andExpect(status().isForbidden());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }


    /**
     * Try to access an organization with the appropriate role
     */
    @Test
    public void testAccessGetOrgWithRights() {
        // Build org object to test with
        Organization org = new Organization();
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Serialize org object
        String orgJson = this.serialize(org);
        // Create fake authentication object
        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:idp1:dma", "ROLE_ORG_ADMIN", "");
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:idp1:dma").with(authentication(auth))
                    .header("Origin", "bla")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }

    /**
     * Try to access an organization with the appropriate role as SITE_ADMIN
     */
    @Test
    public void testAccessGetOrgWithRights2() {
        // Build org object to test with
        Organization org = new Organization();
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Serialize org object
        String orgJson = this.serialize(org);
        // Create fake authentication object - note that the user mrn is from a different org that the organization, but the role should overrule that
        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:idp1:sma", "ROLE_SITE_ADMIN", "");
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:idp1:dma").with(authentication(auth))
                    .header("Origin", "bla")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }

    /**
     * Try to access an organization with the appropriate role
     */
    @Test
    public void testAccessGetOrgByIdWithRights() {
        // Build org object to test with
        Organization org = new Organization();
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Serialize org object
        String orgJson = this.serialize(org);
        // Create fake authentication object
        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:idp1:dma", "ROLE_ORG_ADMIN", "");
        given(this.organizationService.getOrganizationById(0L)).willReturn(org);
        try {
            mvc.perform(get("/oidc/api/org/id/0").with(authentication(auth))
                    .header("Origin", "bla")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }

    /**
     * Try to access an organization with the appropriate role as SITE_ADMIN
     */
    @Test
    public void testAccessGetOrgByIdWithRights2() {
        // Build org object to test with
        Organization org = new Organization();
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Serialize org object
        String orgJson = this.serialize(org);
        // Create fake authentication object - note that the user mrn is from a different org that the organization, but the role should overrule that
        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:org:idp1:sma", "ROLE_SITE_ADMIN", "");
        given(this.organizationService.getOrganizationById(0L)).willReturn(org);
        try {
            mvc.perform(get("/oidc/api/org/id/0").with(authentication(auth))
                    .header("Origin", "bla")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            fail();
        }
    }


    /**
     * Helper function to serialize an organization to json
     * @param org
     * @return
     */
    private String serialize(Organization org) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            // Convert object to JSON string
            String jsonInString = mapper.writeValueAsString(org);
            //System.out.println(jsonInString);

            // Convert object to JSON string and pretty print
            jsonInString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(org);
            //System.out.println(jsonInString);

            return jsonInString;
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

}
