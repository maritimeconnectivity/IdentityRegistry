/*
 * Copyright 2024 Maritime Connectivity Platform Consortium
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

package net.maritimeconnectivity.identityregistry.utils;

import net.maritimeconnectivity.identityregistry.repositories.DeviceRepository;
import net.maritimeconnectivity.identityregistry.repositories.MMSRepository;
import net.maritimeconnectivity.identityregistry.repositories.OrganizationRepository;
import net.maritimeconnectivity.identityregistry.repositories.ServiceRepository;
import net.maritimeconnectivity.identityregistry.repositories.UserRepository;
import net.maritimeconnectivity.identityregistry.repositories.VesselRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.mockito.BDDMockito.given;
import static org.springframework.test.util.AssertionErrors.assertFalse;
import static org.springframework.test.util.AssertionErrors.assertTrue;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@ContextConfiguration
@WebAppConfiguration
@ActiveProfiles("test")
class ExistsByMrnUtilTests {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mvc;

    @MockBean
    JwtDecoder jwtDecoder;

    @MockBean
    private DeviceRepository deviceRepository;
    @MockBean
    private MMSRepository mmsRepository;
    @MockBean
    private OrganizationRepository organizationRepository;
    @MockBean
    private ServiceRepository serviceRepository;
    @MockBean
    private UserRepository userRepository;
    @MockBean
    private VesselRepository vesselRepository;

    @Autowired
    private ExistsByMrnUtil existsByMrnUtil;

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    /**
     * An MRN should be unique when it is not already used by an entity
     */
    @Test
    void testMrnIsUnique() {
        String mrn = "urn:mrn:mcp:entity:idp1:org1:test";
        assertFalse("MRN should be unique", existsByMrnUtil.isMrnAlreadyUsed(mrn));
    }

    /**
     * An MRN should not be unique when it is already used by an entity
     */
    @Test
    void testMrnIsNotUnique() {
        String mrn = "urn:mrn:mcp:entity:idp1:org1:test";
        given(deviceRepository.existsByMrnIgnoreCase(mrn)).willReturn(true);
        assertTrue("MRN should not be unique", existsByMrnUtil.isMrnAlreadyUsed(mrn));
    }
}
