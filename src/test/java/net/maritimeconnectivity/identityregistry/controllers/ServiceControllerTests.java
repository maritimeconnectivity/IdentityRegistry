/*
 * Copyright 2017 Danish Maritime Authority.
 * Copyright 2020 Maritime Connectivity Platform Consortium
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
import net.maritimeconnectivity.identityregistry.exception.DuplicatedKeycloakEntry;
import net.maritimeconnectivity.identityregistry.model.data.ServicePatch;
import net.maritimeconnectivity.identityregistry.model.database.IdentityProviderAttribute;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.model.database.entities.Service;
import net.maritimeconnectivity.identityregistry.repositories.VesselRepository;
import net.maritimeconnectivity.identityregistry.services.CertificateService;
import net.maritimeconnectivity.identityregistry.services.EntityService;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import net.maritimeconnectivity.identityregistry.services.ServiceService;
import net.maritimeconnectivity.identityregistry.utils.KeycloakAdminUtil;
import net.maritimeconnectivity.identityregistry.utils.MCPIdRegConstants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@ContextConfiguration
@WebAppConfiguration
@ActiveProfiles("test")
class ServiceControllerTests {
    @Autowired
    private WebApplicationContext context;

    private MockMvc mvc;
    @MockBean(value = {ServiceService.class})
    private EntityService<Service> entityService;

    @MockBean
    private OrganizationService organizationService;

    @MockBean
    private KeycloakAdminUtil keycloakAU;

    @MockBean
    private CertificateService certificateService;

    @MockBean
    private VesselRepository vesselRepository;

    @MockBean
    JwtDecoder jwtDecoder;

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders
                .webAppContextSetup(context)
                //.alwaysDo(print())
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    /**
     * Try to create a service with an instance version
     */
    @Test
    void testCreateServiceWithVersion() {
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        service.setName("NW NM Service");
        service.setInstanceVersion("0.3.4");
        service.setIdOrganization(1L);
        String serviceJson = serialize(service);
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
        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "urn:mrn:mcp:org:idp1:dma", "ROLE_ORG_ADMIN,ROLE_SITE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrnNoFilter("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        when(org.getId()).thenReturn(1L);

        try {
            MvcResult result = mvc.perform(post("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service").header("Origin", "bla")
                            .content(serviceJson)
                            .contentType(MediaType.APPLICATION_JSON)
                            .with(authentication(auth)))
                    .andExpect(status().isBadRequest())
                    .andReturn();
            String responseBody = result.getResponse().getContentAsString();
            assertTrue(responseBody.contains(MCPIdRegConstants.INSTANCE_VERSION_NOT_ALLOWED));
        } catch (Exception e) {
            fail(e);
        }
    }

    /**
     * Try to create a service without an instance version
     */
    @Test
    void testCreateServiceWithoutVersion() {
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        service.setName("NW NM Service");
        service.setIdOrganization(1L);
        String serviceJson = serialize(service);
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
        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "urn:mrn:mcp:org:idp1:dma", "ROLE_ORG_ADMIN,ROLE_SITE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrnNoFilter("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        when(org.getId()).thenReturn(1L);
        when(entityService.save(any())).thenReturn(service);

        try {
            mvc.perform(post("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service").header("Origin", "bla")
                            .content(serviceJson)
                            .contentType(MediaType.APPLICATION_JSON)
                            .with(authentication(auth)))
                    .andExpect(status().isCreated())
                    .andExpect(content().json(serviceJson, false));
        } catch (Exception e) {
            fail(e);
        }
    }

    /**
     * Try to get a service without being authenticated
     */
    @WithMockUser()
    @Test
    void testAccessGetServiceWithVersionWithoutRights() {
        given(this.entityService.getByMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm")).willReturn(new Service());
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm/0.3.4").header("Origin", "bla")).andExpect(status().isForbidden());
        } catch (Exception e) {
            fail(e);
        }
    }

    /**
     * Try to get a service without being authenticated
     */
    @WithMockUser()
    @Test
    void testAccessGetServiceWithoutVersionWithoutRights() {
        given(this.entityService.getByMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm")).willReturn(new Service());
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm").header("Origin", "bla")).andExpect(status().isForbidden());
        } catch (Exception e) {
            fail(e);
        }
    }

    /**
     * Try to get a service with the appropriate association
     */
    @Test
    void testAccessGetServiceWithVersionWithRights() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        service.setName("NW NM Service");
        service.setInstanceVersion("0.3.4");
        service.setIdOrganization(1L);
        String serviceJson = serialize(service);
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
        JwtAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "urn:mrn:mcp:org:idp1:dma", "ROLE_USER", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.organizationService.getOrganizationByMrnNoFilter("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(((ServiceService) this.entityService).getServiceByMrnAndVersion("urn:mrn:mcp:service:idp1:dma:instance:nw-nm", "0.3.4")).willReturn(service);
        when(org.getId()).thenReturn(1L);
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm/0.3.4").with(authentication(auth))
                    .header("Origin", "bla")
            ).andExpect(status().isOk()).andExpect(content().json(serviceJson, false));
        } catch (Exception e) {
            fail(e);
        }
        verify(((ServiceService) this.entityService), atLeastOnce()).getServiceByMrnAndVersion("urn:mrn:mcp:service:idp1:dma:instance:nw-nm", "0.3.4");
    }

    /**
     * Try to get a service with the appropriate association
     */
    @Test
    void testAccessGetServiceWithoutVersionWithRights() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        service.setName("NW NM Service");
        service.setIdOrganization(1L);
        String serviceJson = serialize(service);
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
        JwtAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "urn:mrn:mcp:org:idp1:dma", "ROLE_USER", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.organizationService.getOrganizationByMrnNoFilter("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(((ServiceService) this.entityService).getByMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm")).willReturn(service);
        when(org.getId()).thenReturn(1L);
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm").with(authentication(auth))
                    .header("Origin", "bla")
            ).andExpect(status().isOk()).andExpect(content().json(serviceJson, false));
        } catch (Exception e) {
            fail(e);
        }
        verify(((ServiceService) this.entityService), atLeastOnce()).getByMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
    }

    /**
     * Try to get a service with the appropriate rights, but different org
     */
    @Test
    void testAccessGetServiceWithRights2() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        service.setName("NW NM Service");
        service.setInstanceVersion("0.3.4");
        service.setIdOrganization(1L);
        String serviceJson = serialize(service);
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
        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:sma:user", "urn:mrn:mcp:org:idp1:sma", "ROLE_ORG_ADMIN,ROLE_SITE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:sma")).willReturn(org);
        given(((ServiceService) this.entityService).getServiceByMrnAndVersion("urn:mrn:mcp:service:idp1:dma:instance:nw-nm", "0.3.4")).willReturn(service);
        when(org.getId()).thenReturn(1L);
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm/0.3.4").with(authentication(auth))
                    .header("Origin", "bla")
            ).andExpect(status().isOk()).andExpect(content().json(serviceJson, false));
        } catch (Exception e) {
            fail(e);
        }
    }


    /**
     * Try to update a service without the appropriate association
     */
    @Test
    void testAccessUpdateServiceWithoutRights() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        service.setName("NW NM Service");
        service.setInstanceVersion("0.3.4");
        service.setIdOrganization(1L);
        String serviceJson = serialize(service);
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
        JwtAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "urn:mrn:mcp:org:idp1:dma", "ROLE_USER_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrnNoFilter("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(((ServiceService) this.entityService).getServiceByMrnAndVersion("urn:mrn:mcp:service:idp1:dma:instance:nw-nm", "0.3.4")).willReturn(service);
        when(org.getId()).thenReturn(1L);
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm/0.3.4").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(serviceJson)
                    .contentType("application/json")
            ).andExpect(status().isForbidden());
        } catch (Exception e) {
            fail(e);
        }
    }

    /**
     * Try to update a service with the appropriate association
     */
    @Test
    void testAccessUpdateServiceWithRights() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm:0.3.4");
        service.setName("NW NM Service");
        service.setIdOrganization(1L);
        service.setOidcAccessType("bearer-only");
        service.setOidcRedirectUri("https://localhost");
        String serviceJson = serialize(service);
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
        JwtAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "urn:mrn:mcp:org:idp1:dma", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrnNoFilter("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm:0.3.4")).willReturn(service);
        when(org.getId()).thenReturn(1L);
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm:0.3.4").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(serviceJson)
                    .contentType("application/json")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            fail(e);
        }
        try {
            verify(this.keycloakAU, times(1)).createClient("urn:mrn:mcp:service:idp1:dma:instance:nw-nm:0.3.4", "bearer-only", "https://localhost");
        } catch (IOException | DuplicatedKeycloakEntry e) {
            fail(e);
        }
    }

    /**
     * Try to get a JBoss conf XML for a service
     */
    @Test
    void testAccessServiceJBossXMLWithRights() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm:0.3.4");
        service.setName("NW NM Service");
        service.setIdOrganization(1L);
        service.setOidcAccessType("bearer-only");
        service.generateOidcClientId();
        String serviceJson = serialize(service);
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
        JwtAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "urn:mrn:mcp:org:idp1:dma", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.organizationService.getOrganizationByMrnNoFilter("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm:0.3.4")).willReturn(service);
        when(org.getId()).thenReturn(1L);
        try {
            given(this.keycloakAU.getClientJbossXml("urn:mrn:mcp:service:idp1:dma:instance:nw-nm:0.3.4")).willReturn("<secure-deployment name=\"WAR MODULE NAME.war\"><realm>MaritimeCloud</realm>...</secure-deployment>");
        } catch (IOException e) {
            fail(e);
        }
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm:0.3.4/jbossxml").with(authentication(auth))
                    .header("Origin", "bla")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            fail(e);
        }
    }

    /**
     * Try to get a JBoss conf XML for a service where it is not available
     */
    @Test
    void testAccessServiceJBossXMLWithRightsNoConf() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        service.setName("NW NM Service");
        service.setInstanceVersion("0.3.4");
        service.setIdOrganization(1L);
        service.setOidcAccessType(null);
        String serviceJson = serialize(service);
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
        JwtAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "urn:mrn:mcp:org:idp1:dma", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.organizationService.getOrganizationByMrnNoFilter("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(((ServiceService) this.entityService).getServiceByMrnAndVersion("urn:mrn:mcp:service:idp1:dma:instance:nw-nm", "0.3.4")).willReturn(service);
        when(org.getId()).thenReturn(1L);
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm/0.3.4/jbossxml").with(authentication(auth))
                    .header("Origin", "bla")
            ).andExpect(status().isNotFound());
        } catch (Exception e) {
            fail(e);
        }
    }

    /**
     * Try to update a service with valid OIDC info
     */
    @Test
    void testUpdateServiceWithValidOIDC() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        service.setName("NW NM Service");
        service.setIdOrganization(1L);
        service.setOidcAccessType("public");
        service.setOidcRedirectUri("https://localhost");
        String serviceJson = serialize(service);
        // Old service that we want to update
        Service oldService = new Service();
        oldService.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        oldService.setName("NW NM Service");
        oldService.setIdOrganization(1L);
        oldService.setOidcAccessType("bearer-only");
        oldService.setOidcClientId("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
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
        JwtAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "urn:mrn:mcp:org:idp1:dma", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrnNoFilter("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm")).willReturn(oldService);
        when(org.getId()).thenReturn(1L);
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(serviceJson)
                    .contentType("application/json")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            fail(e);
        }
        try {
            verify(this.keycloakAU, times(1)).updateClient("urn:mrn:mcp:service:idp1:dma:instance:nw-nm", "public", "https://localhost");
        } catch (IOException e) {
            fail(e);
        }
    }

    /**
     * Try to update a service with invalid OIDC info
     */
    @Test
    void testUpdateServiceWithInvalidOIDC() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        service.setName("NW NM Service");
        service.setIdOrganization(1L);
        service.setOidcAccessType("public");
        //service.setOidcRedirectUri("https://localhost");
        String serviceJson = serialize(service);
        // Old service that we want to update
        Service oldService = new Service();
        oldService.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        oldService.setName("NW NM Service");
        oldService.setIdOrganization(1L);
        oldService.setOidcAccessType("bearer-only");
        oldService.setOidcClientId("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
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
        JwtAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "urn:mrn:mcp:org:idp1:dma", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrnNoFilter("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm")).willReturn(oldService);
        when(org.getId()).thenReturn(1L);
        try {
            MvcResult result = mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(serviceJson)
                    .contentType("application/json")
            ).andExpect(status().isBadRequest()).andReturn();
            String stringResult = result.getResponse().getContentAsString();
            assertTrue(stringResult.contains(MCPIdRegConstants.OIDC_MISSING_REDIRECT_URL));
        } catch (Exception e) {
            fail(e);
        }
    }

    /**
     * Try to update a service with valid OIDC info
     */
    @Test
    void testUpdateServiceWithVersionRemoveOIDC() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        service.setName("NW NM Service");
        service.setInstanceVersion("0.3.4");
        service.setIdOrganization(1L);
        String serviceJson = serialize(service);
        // Old service that we want to update
        Service oldService = new Service();
        oldService.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        oldService.setName("NW NM Service");
        oldService.setInstanceVersion("0.3.4");
        oldService.setIdOrganization(1L);
        oldService.setOidcAccessType("bearer-only");
        oldService.setOidcClientId("0.3.4-urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
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
        JwtAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "urn:mrn:mcp:org:idp1:dma", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrnNoFilter("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(((ServiceService) this.entityService).getServiceByMrnAndVersion("urn:mrn:mcp:service:idp1:dma:instance:nw-nm", "0.3.4")).willReturn(oldService);
        when(org.getId()).thenReturn(1L);
        try {
            MvcResult result = mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm/0.3.4").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(serviceJson)
                    .contentType("application/json")
            ).andExpect(status().isMethodNotAllowed()).andReturn();

            String responseBody = result.getResponse().getContentAsString();
            assertTrue(responseBody.contains("A Service with a version must be migrated before it can be updated."));
        } catch (Exception e) {
            fail(e);
        }
    }

    /**
     * Try to update a service with valid OIDC info
     */
    @Test
    void testUpdateServiceWithoutVersionRemoveOIDC() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        service.setName("NW NM Service");
        service.setIdOrganization(1L);
        String serviceJson = serialize(service);
        // Old service that we want to update
        Service oldService = new Service();
        oldService.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        oldService.setName("NW NM Service");
        oldService.setIdOrganization(1L);
        oldService.setOidcAccessType("bearer-only");
        oldService.setOidcClientId("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
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
        JwtAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "urn:mrn:mcp:org:idp1:dma", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrnNoFilter("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.entityService.getByMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm")).willReturn(oldService);
        when(org.getId()).thenReturn(1L);
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(serviceJson)
                    .contentType("application/json")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            fail(e);
        }
        verify(this.keycloakAU, times(1)).deleteClient("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
    }

    @Test
    void tryCreatingServiceWithMrnAlreadyUsedByVessel() {
        String mrn = "urn:mrn:mcp:entity:idp1:org1:test";
        given(vesselRepository.existsByMrnIgnoreCase(mrn)).willReturn(true);
        Service service = new Service();
        service.setMrn(mrn);
        service.setName("Service");
        service.setIdOrganization(1L);
        String serviceJson = serialize(service);

        Organization org = spy(Organization.class);
        org.setMrn("urn:mrn:mcp:entity:idp1:org1");
        org.setName("Test Org");
        org.setCountry("Nowhere");
        org.setUrl("https://example.com");
        org.setEmail("test@example.com");
        org.setAddress("Middle of Nowhere 12");
        Set<IdentityProviderAttribute> identityProviderAttributes = new HashSet<>();
        org.setIdentityProviderAttributes(identityProviderAttributes);
        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:entity:idp1:org1:user", "urn:mrn:mcp:entity:idp1:org1", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrnNoFilter("urn:mrn:mcp:entity:idp1:org1")).willReturn(org);
        when(org.getId()).thenReturn(1L);

        try {
            MvcResult result = mvc.perform(post("/oidc/api/org/urn:mrn:mcp:entity:idp1:org1/service").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(serviceJson)
                    .contentType("application/json")
            ).andExpect(status().isConflict()).andReturn();
            String responseBody = result.getResponse().getContentAsString();
            assertTrue(responseBody.contains(MCPIdRegConstants.ENTITY_WITH_MRN_ALREADY_EXISTS));
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testMigrateExistingService() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        service.setName("NW NM Service");
        service.setInstanceVersion("0.3.4");
        service.setIdOrganization(1L);
        service.setCertificates(Set.of());
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
        JwtAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user",
                "urn:mrn:mcp:org:idp1:dma", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.organizationService.getOrganizationByMrnNoFilter("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        when(org.getId()).thenReturn(1L);
        given(((ServiceService) this.entityService).getServiceByMrnAndVersion(service.getMrn(), service.getInstanceVersion())).willReturn(service);

        ServicePatch servicePatch = new ServicePatch();
        servicePatch.setMrn(service.getMrn() + ":" + service.getInstanceVersion());
        String patchJson = serialize(servicePatch);

        try {
            MvcResult result = mvc.perform(patch("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm/0.3.4/migrate")
                    .with(authentication(auth))
                    .header("Origin", "bla")
                    .content(patchJson)
                    .contentType("application/json")
            ).andExpect(status().isNoContent()).andReturn();
            String location = result.getResponse().getHeader("Location");
            assertEquals("http://localhost/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm:0.3.4", location);
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testMigrateExistingServiceSameMrn() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        service.setName("NW NM Service");
        service.setInstanceVersion("0.3.4");
        service.setIdOrganization(1L);
        service.setCertificates(Set.of());
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
        JwtAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user",
                "urn:mrn:mcp:org:idp1:dma", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.organizationService.getOrganizationByMrnNoFilter("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        when(org.getId()).thenReturn(1L);
        given(((ServiceService) this.entityService).getServiceByMrnAndVersion(service.getMrn(), service.getInstanceVersion())).willReturn(service);

        ServicePatch servicePatch = new ServicePatch();
        servicePatch.setMrn(service.getMrn());
        String patchJson = serialize(servicePatch);

        try {
            MvcResult result = mvc.perform(patch("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm/0.3.4/migrate")
                    .with(authentication(auth))
                    .header("Origin", "bla")
                    .content(patchJson)
                    .contentType("application/json")
            ).andExpect(status().isNoContent()).andReturn();
            String location = result.getResponse().getHeader("Location");
            assertEquals("http://localhost/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm", location);
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testMigrateExistingServiceConflictingMrn() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        service.setName("NW NM Service");
        service.setInstanceVersion("0.3.4");
        service.setIdOrganization(1L);
        service.setCertificates(Set.of());
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
        JwtAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user",
                "urn:mrn:mcp:org:idp1:dma", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.organizationService.getOrganizationByMrnNoFilter("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        when(org.getId()).thenReturn(1L);
        given(((ServiceService) this.entityService).getServiceByMrnAndVersion(service.getMrn(), service.getInstanceVersion())).willReturn(service);

        String newMrn = "urn:mrn:mcp:entity:idp1:dma:instance:nw-nm";
        // For whatever reason there is already an organization that is using the new MRN
        given(this.organizationService.existsByMrn(newMrn)).willReturn(true);

        ServicePatch servicePatch = new ServicePatch();
        servicePatch.setMrn(newMrn);
        String patchJson = serialize(servicePatch);

        try {
            mvc.perform(patch("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm/0.3.4/migrate")
                    .with(authentication(auth))
                    .header("Origin", "bla")
                    .content(patchJson)
                    .contentType("application/json")
            ).andExpect(status().isConflict());
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testMigrateExistingServiceConflictingMrn2() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        service.setName("NW NM Service");
        service.setInstanceVersion("0.3.4");
        service.setIdOrganization(1L);
        service.setCertificates(Set.of());
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
        JwtAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user",
                "urn:mrn:mcp:org:idp1:dma", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.organizationService.getOrganizationByMrnNoFilter("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        when(org.getId()).thenReturn(1L);
        given(((ServiceService) this.entityService).getServiceByMrnAndVersion(service.getMrn(), service.getInstanceVersion())).willReturn(service);

        String newMrn = "urn:mrn:mcp:entity:idp1:dma:instance:nw-nm";
        // For whatever reason there is already another service that is using the new MRN
        given(this.entityService.existsByMrn(newMrn)).willReturn(true);
        given(((ServiceService) this.entityService).getServiceByMrnAndVersion(newMrn, null)).willReturn(new Service());

        ServicePatch servicePatch = new ServicePatch();
        servicePatch.setMrn(newMrn);
        String patchJson = serialize(servicePatch);

        try {
            mvc.perform(patch("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm/0.3.4/migrate")
                    .with(authentication(auth))
                    .header("Origin", "bla")
                    .content(patchJson)
                    .contentType("application/json")
            ).andExpect(status().isConflict());
        } catch (Exception e) {
            fail(e);
        }
    }

    /**
     * Helper function to serialize a service to json
     *
     * @param object the object to be JSON serialized
     * @return JSON representation of service
     */
    private String serialize(Object object) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            // Convert object to JSON string and pretty print
            return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(object);
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }
}
