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

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.maritimecloud.identityregistry.model.database.IdentityProviderAttribute;
import net.maritimecloud.identityregistry.model.database.Organization;
import net.maritimecloud.identityregistry.model.database.entities.Service;
import net.maritimecloud.identityregistry.services.CertificateService;
import net.maritimecloud.identityregistry.services.EntityService;
import net.maritimecloud.identityregistry.services.OrganizationService;
import net.maritimecloud.identityregistry.utils.AccessControlUtil;
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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertTrue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@ContextConfiguration
@WebAppConfiguration
public class ServiceControllerTests {
    @Autowired
    private WebApplicationContext context;

    private MockMvc mvc;
    @MockBean
    private EntityService<Service> entityService;

    @MockBean
    private OrganizationService organizationService;

    @MockBean
    private KeycloakAdminUtil keycloakAU;

    @MockBean
    private CertificateService certificateService;

    @MockBean
    private AccessControlUtil accessControlUtil;
    @Before
    public void setup() {
        mvc = MockMvcBuilders
                .webAppContextSetup(context)
                .alwaysDo(print())
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }


    /**
     * Try to get a service without being authenticated
     */
    @WithMockUser()
    @Test
    public void testAccessGetServiceWithoutRights() {
        given(this.entityService.getByMrn("urn:mrn:mcl:service:instance:dma:nw-nm")).willReturn(new Service());
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcl:org:dma/service/urn:mrn:mcl:service:instance:dma:nw-nm").header("Origin", "bla")).andExpect(status().isForbidden());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Try to get a service with the appropriate association
     */
    @Test
    public void testAccessGetServiceWithRights() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcl:service:instance:dma:nw-nm");
        service.setName("NW NM Service");
        service.setIdOrganization(new Long(1));
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcl:org:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        List<IdentityProviderAttribute> identityProviderAttributes = new ArrayList<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Create fake authentication token
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcl:org:dma", "ROLE_USER", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcl:org:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcl:service:instance:dma:nw-nm")).willReturn(service);
        when(org.getId()).thenReturn(new Long(1));
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcl:org:dma/service/urn:mrn:mcl:service:instance:dma:nw-nm").with(authentication(auth))
                    .header("Origin", "bla")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Try to get a service with the appropriate rights, but different org
     */
    @Test
    public void testAccessGetServiceWithRights2() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcl:service:instance:dma:nw-nm");
        service.setName("NW NM Service");
        service.setIdOrganization(new Long(1));
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcl:org:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        List<IdentityProviderAttribute> identityProviderAttributes = new ArrayList<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Create fake authentication token, note that the user mrn is different from the org mrn, but being SITE_ADMIN should overrule that
        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcl:org:sma", "ROLE_ORG_ADMIN,ROLE_SITE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcl:org:dma")).willReturn(org);
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcl:org:sma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcl:service:instance:dma:nw-nm")).willReturn(service);
        when(org.getId()).thenReturn(new Long(1));
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcl:org:dma/service/urn:mrn:mcl:service:instance:dma:nw-nm").with(authentication(auth))
                    .header("Origin", "bla")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }


    /**
     * Try to update a service without the appropriate association
     */
    @Test
    public void testAccessUpdateServiceWithoutRights() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcl:service:instance:dma:nw-nm");
        service.setName("NW NM Service");
        service.setIdOrganization(new Long(1));
        String serviceJson = serialize(service);
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcl:org:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        List<IdentityProviderAttribute> identityProviderAttributes = new ArrayList<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Create fake authentication token
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcl:org:dma", "ROLE_USER_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcl:org:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcl:service:instance:dma:nw-nm")).willReturn(service);
        when(org.getId()).thenReturn(new Long(1));
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcl:org:dma/service/urn:mrn:mcl:service:instance:dma:nw-nm").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(serviceJson)
                    .contentType("application/json")
            ).andExpect(status().isForbidden());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Try to update a service without the appropriate association
     */
    @Test
    public void testAccessUpdateServiceWithRights() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcl:service:instance:dma:nw-nm");
        service.setName("NW NM Service");
        service.setIdOrganization(new Long(1));
        String serviceJson = serialize(service);
        // Build org object to test with
        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcl:org:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        List<IdentityProviderAttribute> identityProviderAttributes = new ArrayList<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        // Create fake authentication token
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcl:org:dma", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcl:org:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcl:service:instance:dma:nw-nm")).willReturn(service);
        when(org.getId()).thenReturn(new Long(1));
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcl:org:dma/service/urn:mrn:mcl:service:instance:dma:nw-nm").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(serviceJson)
                    .contentType("application/json")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
    }

    /**
     * Helper function to serialize an organization to json
     * @param service
     * @return
     */
    private String serialize(Service service) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            // Convert object to JSON string
            String jsonInString = mapper.writeValueAsString(service);
            //System.out.println(jsonInString);

            // Convert object to JSON string and pretty print
            jsonInString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(service);
            //System.out.println(jsonInString);

            return jsonInString;
        } catch (JsonGenerationException e) {
            e.printStackTrace();
        } catch (JsonMappingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}
