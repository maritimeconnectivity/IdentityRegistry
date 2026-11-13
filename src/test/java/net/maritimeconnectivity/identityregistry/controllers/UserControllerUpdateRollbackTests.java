/*
 * Copyright 2026 Maritime Connectivity Platform Consortium
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

import net.maritimeconnectivity.identityregistry.exception.McpBasicRestException;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.model.database.entities.User;
import net.maritimeconnectivity.identityregistry.repositories.OrganizationRepository;
import net.maritimeconnectivity.identityregistry.repositories.UserRepository;
import net.maritimeconnectivity.identityregistry.utils.KeycloakAdminUtil;
import net.maritimeconnectivity.identityregistry.utils.MCPIdRegConstants;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.io.IOException;
import java.util.HashSet;

import static net.maritimeconnectivity.identityregistry.controllers.JSONSerializer.serialize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Regression test for updating a user when the Keycloak update fails (issue #70).
 * <p>
 * Unlike {@link UserControllerTests}, this uses the real services and the H2 database, so it can
 * check what is actually stored. Only Keycloak is mocked.
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest
@ContextConfiguration
@WebAppConfiguration
@ActiveProfiles("test")
class UserControllerUpdateRollbackTests {
    private static final String ORG_MRN = "urn:mrn:mcp:org:idp1:rollback";
    private static final String USER_MRN = "urn:mrn:mcp:user:idp1:rollback:jdoe";
    private static final String OLD_EMAIL = "old@example.com";
    private static final String NEW_EMAIL = "new@example.com";
    private static final String OLD_FIRST_NAME = "John";
    private static final String NEW_FIRST_NAME = "Jonathan";
    private static final String LAST_NAME = "Doe";

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private OrganizationRepository organizationRepository;

    @Autowired
    private UserRepository userRepository;

    @MockitoBean
    private KeycloakAdminUtil keycloakAU;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    private MockMvc mvc;

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();

        Organization org = new Organization();
        org.setMrn(ORG_MRN);
        org.setName("Rollback Test Org");
        org.setEmail("org@example.com");
        org.setUrl("https://example.com");
        org.setAddress("Example Street 1");
        org.setCountry("Denmark");
        org.setApproved(true);
        org.setFederationType("test-idp");
        org.setCertificateAuthority("TEST_CA");
        org.setIdentityProviderAttributes(new HashSet<>());
        org = organizationRepository.save(org);

        User user = new User();
        user.setMrn(USER_MRN);
        user.setFirstName(OLD_FIRST_NAME);
        user.setLastName(LAST_NAME);
        user.setEmail(OLD_EMAIL);
        user.setIdOrganization(org.getId());
        userRepository.save(user);
    }

    @AfterEach
    void cleanup() {
        User user = userRepository.getByMrnIgnoreCase(USER_MRN);
        if (user != null) {
            userRepository.delete(user);
        }
        Organization org = organizationRepository.findByMrn(ORG_MRN);
        if (org != null) {
            organizationRepository.delete(org);
        }
    }

    @Test
    void failedKeycloakUpdateDoesNotChangeUserInDatabase() throws Exception {
        // This is what KeycloakAdminUtil.updateUser throws when it can't find a user with the new e-mail address
        doThrow(new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.USER_EMAIL_UPDATE_NOT_ALLOWED, ""))
                .when(keycloakAU).updateUser(any(), any(), any(), any(), any(), any(), any(), any(), any());

        performUpdate(OLD_FIRST_NAME, NEW_EMAIL).andExpect(status().isBadRequest());

        User stored = userRepository.getByMrnIgnoreCase(USER_MRN);
        assertNotNull(stored);
        assertEquals(OLD_EMAIL, stored.getEmail(), "The user should keep its old e-mail address when the Keycloak update fails");
    }

    @Test
    void keycloakIOExceptionDoesNotChangeUserInDatabase() throws Exception {
        // KeycloakAdminUtil.updateUser throws an IOException when it finds more than one user with the e-mail address
        doThrow(new IOException("User update failed! Found 2 users while trying to update, expected 1"))
                .when(keycloakAU).updateUser(any(), any(), any(), any(), any(), any(), any(), any(), any());

        performUpdate(NEW_FIRST_NAME, OLD_EMAIL).andExpect(status().isInternalServerError());

        User stored = userRepository.getByMrnIgnoreCase(USER_MRN);
        assertNotNull(stored);
        assertEquals(OLD_FIRST_NAME, stored.getFirstName(), "The user should keep its old first name when the Keycloak update fails");
    }

    private ResultActions performUpdate(String firstName, String email) throws Exception {
        User input = new User();
        input.setMrn(USER_MRN);
        input.setFirstName(firstName);
        input.setLastName(LAST_NAME);
        input.setEmail(email);

        JwtAuthenticationToken auth = TokenGenerator.generateKeycloakToken(USER_MRN, ORG_MRN, "ROLE_USER_ADMIN", "");

        return mvc.perform(put("/oidc/api/org/" + ORG_MRN + "/user/" + USER_MRN)
                .with(authentication(auth))
                .header("Origin", "bla")
                .content(serialize(input))
                .contentType("application/json")
        );
    }
}
