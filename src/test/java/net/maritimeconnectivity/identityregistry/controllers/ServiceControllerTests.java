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
import net.maritimeconnectivity.identityregistry.exception.DuplicatedKeycloakEntry;
import net.maritimeconnectivity.identityregistry.model.database.IdentityProviderAttribute;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.model.database.entities.Service;
import net.maritimeconnectivity.identityregistry.services.CertificateService;
import net.maritimeconnectivity.identityregistry.services.EntityService;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import net.maritimeconnectivity.identityregistry.services.ServiceService;
import net.maritimeconnectivity.identityregistry.utils.KeycloakAdminUtil;
import net.maritimeconnectivity.identityregistry.utils.MCPIdRegConstants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
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

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

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
public class ServiceControllerTests {
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

    @BeforeEach
    public void setup() {
        mvc = MockMvcBuilders
                .webAppContextSetup(context)
                //.alwaysDo(print())
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }


    /**
     * Try to get a service without being authenticated
     */
    @WithMockUser()
    @Test
    public void testAccessGetServiceWithoutRights() {
        given(this.entityService.getByMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm")).willReturn(new Service());
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm/0.3.4").header("Origin", "bla")).andExpect(status().isForbidden());
        } catch (Exception e) {
            fail(e);
        }
    }

    /**
     * Try to get a service with the appropriate association
     */
    @Test
    public void testAccessGetServiceWithRights() {
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
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "ROLE_USER", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
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
     * Try to get a service with the appropriate rights, but different org
     */
    @Test
    public void testAccessGetServiceWithRights2() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        service.setName("NW NM Service");
        service.setInstanceVersion("0.3.4");
        service.setIdOrganization(1L);
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
        Authentication auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:sma:user", "ROLE_ORG_ADMIN,ROLE_SITE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:sma")).willReturn(org);
        given(((ServiceService) this.entityService).getServiceByMrnAndVersion("urn:mrn:mcp:service:idp1:dma:instance:nw-nm", "0.3.4")).willReturn(service);
        when(org.getId()).thenReturn(1L);
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm/0.3.4").with(authentication(auth))
                    .header("Origin", "bla")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            fail(e);
        }
    }


    /**
     * Try to update a service without the appropriate association
     */
    @Test
    public void testAccessUpdateServiceWithoutRights() {
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
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "ROLE_USER_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
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
    public void testAccessUpdateServiceWithRights() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        service.setName("NW NM Service");
        service.setInstanceVersion("0.3.4");
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
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(((ServiceService) this.entityService).getServiceByMrnAndVersion("urn:mrn:mcp:service:idp1:dma:instance:nw-nm", "0.3.4")).willReturn(service);
        when(org.getId()).thenReturn(1L);
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm/0.3.4").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(serviceJson)
                    .contentType("application/json")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            fail(e);
        }
        try {
            verify(this.keycloakAU, times(1)).createClient("0.3.4-urn:mrn:mcp:service:idp1:dma:instance:nw-nm", "bearer-only", "https://localhost");
        } catch (IOException | DuplicatedKeycloakEntry e) {
            fail(e);
        }
    }

    /**
     * Try to update a service with the appropriate association but with version set to null
     */
    @Test
    public void testCreateServiceWithVersionNull() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        service.setName("NW NM Service");
        service.setInstanceVersion(null);
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
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        when(org.getId()).thenReturn(1L);
        try {
            mvc.perform(post("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(serviceJson)
                    .contentType("application/json")
            ).andExpect(status().isBadRequest());
        } catch (Exception e) {
            fail(e);
        }
    }

    /**
     * Try to get a JBoss conf XML for a service
     */
    @Test
    public void testAccessServiceJBossXMLWithRights() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        service.setName("NW NM Service");
        service.setInstanceVersion("0.3.4");
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
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(((ServiceService) this.entityService).getServiceByMrnAndVersion("urn:mrn:mcp:service:idp1:dma:instance:nw-nm", "0.3.4")).willReturn(service);
        when(org.getId()).thenReturn(1L);
        given(this.keycloakAU.getClientJbossXml("0.3.4-urn:mrn:mcp:service:idp1:dma:instance:nw-nm")).willReturn("<secure-deployment name=\"WAR MODULE NAME.war\"><realm>MaritimeCloud</realm>...</secure-deployment>");
        try {
            mvc.perform(get("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm/0.3.4/jbossxml").with(authentication(auth))
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
    public void testAccessServiceJBossXMLWithRightsNoConf() {
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
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
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
    public void testUpdateServiceWithValidOIDC() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        service.setName("NW NM Service");
        service.setInstanceVersion("0.3.4");
        service.setIdOrganization(1L);
        service.setOidcAccessType("public");
        service.setOidcRedirectUri("https://localhost");
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
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(((ServiceService) this.entityService).getServiceByMrnAndVersion("urn:mrn:mcp:service:idp1:dma:instance:nw-nm", "0.3.4")).willReturn(oldService);
        when(org.getId()).thenReturn(1L);
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm/0.3.4").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(serviceJson)
                    .contentType("application/json")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            fail(e);
        }
        try {
            verify(this.keycloakAU, times(1)).updateClient("0.3.4-urn:mrn:mcp:service:idp1:dma:instance:nw-nm", "public", "https://localhost");
        } catch (IOException e) {
            fail(e);
        }
    }

    /**
     * Try to update a service with invalid OIDC info
     */
    @Test
    public void testUpdateServiceWithInvalidOIDC() {
        // Build service object to test with
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
        service.setName("NW NM Service");
        service.setInstanceVersion("0.3.4");
        service.setIdOrganization(1L);
        service.setOidcAccessType("public");
        //service.setOidcRedirectUri("https://localhost");
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
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(((ServiceService) this.entityService).getServiceByMrnAndVersion("urn:mrn:mcp:service:idp1:dma:instance:nw-nm", "0.3.4")).willReturn(oldService);
        when(org.getId()).thenReturn(1L);
        try {
            MvcResult result = mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm/0.3.4").with(authentication(auth))
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
    public void testUpdateServiceRemoveOIDC() {
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
        KeycloakAuthenticationToken auth = TokenGenerator.generateKeycloakToken("urn:mrn:mcp:user:idp1:dma:user", "ROLE_SERVICE_ADMIN", "");
        // Setup mock returns
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcp:org:idp1:dma")).willReturn(org);
        given(((ServiceService) this.entityService).getServiceByMrnAndVersion("urn:mrn:mcp:service:idp1:dma:instance:nw-nm", "0.3.4")).willReturn(oldService);
        when(org.getId()).thenReturn(1L);
        try {
            mvc.perform(put("/oidc/api/org/urn:mrn:mcp:org:idp1:dma/service/urn:mrn:mcp:service:idp1:dma:instance:nw-nm/0.3.4").with(authentication(auth))
                    .header("Origin", "bla")
                    .content(serviceJson)
                    .contentType("application/json")
            ).andExpect(status().isOk());
        } catch (Exception e) {
            fail(e);
        }
        verify(this.keycloakAU, times(1)).deleteClient("0.3.4-urn:mrn:mcp:service:idp1:dma:instance:nw-nm");
    }


    /**
     * Helper function to serialize a service to json
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
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }
}
