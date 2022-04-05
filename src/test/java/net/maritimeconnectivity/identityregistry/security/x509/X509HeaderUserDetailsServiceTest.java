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
package net.maritimeconnectivity.identityregistry.security.x509;

import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.model.database.Role;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import net.maritimeconnectivity.identityregistry.services.RoleService;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;

@ExtendWith(SpringExtension.class)
@ActiveProfiles("test")
class X509HeaderUserDetailsServiceTest {

    @MockBean
    private RoleService roleService;
    @MockBean
    private OrganizationService organizationService;

    @InjectMocks
    X509HeaderUserDetailsService x509HeaderUserDetailsService;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void loadUserByUsernameVessel1() throws Exception {
        // Load certificate from file
        String certFile = "src/test/resources/Certificate_Myboat.pem";
        String contents = null;
        try (FileInputStream fileInputStream = new FileInputStream(certFile)) {
            contents = IOUtils.toString(fileInputStream, StandardCharsets.UTF_8);
        } catch (IOException e) {
            fail("Loading Certificate from file failed!", e);
        }
        // Try to get user from certificate
        InetOrgPerson person = (InetOrgPerson) x509HeaderUserDetailsService.loadUserByUsername(contents);
        // Validate the user object
        assertEquals("urn:mrn:mcl:vessel:dma:myboat", person.getUsername());
        assertEquals("urn:mrn:mcl:vessel:dma:myboat", person.getUid());
        assertEquals("urn:mrn:mcl:org:dma", person.getO());
        assertEquals("vessel", person.getOu());
        assertEquals(1, person.getCn().length);
        assertEquals("My Boat", person.getCn()[0]);
        assertEquals("DK", person.getPostalAddress());
        assertEquals(1, person.getAuthorities().size());
        assertEquals("ROLE_USER", person.getAuthorities().iterator().next().getAuthority());
    }

    //@Test
    void loadUserByUsernameVessel2() throws Exception {
        // Load certificate from file
        String certFile = "src/test/resources/Certificate_My_vessel.pem";
        String contents = null;
        try {
            contents = Files.lines(Paths.get(certFile)).collect(Collectors.joining("\n"));
        } catch (IOException e) {
            fail("Loading Certificate from file failed!", e);
        }
        // Setup mocked role
        Role role = new Role();
        role.setPermission("routeplanner");
        role.setRoleName("ROLE_ROUTEPLANNER");
        given(this.roleService.getRolesByIdOrganizationAndPermission(any(Long.class), eq("routeplanner"))).willReturn(Collections.singletonList(role));
        // Setup mocked org
        given(this.organizationService.getOrganizationByMrn("urn:mrn:mcl:org:dma")).willReturn(new Organization());
        // Try to get user from certificate
        InetOrgPerson person = (InetOrgPerson) x509HeaderUserDetailsService.loadUserByUsername(contents);
        // Validate the user object
        assertEquals("urn:mrn:mcl:vessel:dma:ves", person.getUsername());
        assertEquals("urn:mrn:mcl:vessel:dma:ves", person.getUid());
        assertEquals("urn:mrn:mcl:org:dma", person.getO());
        assertEquals("vessel", person.getOu());
        assertEquals(1, person.getCn().length);
        assertEquals("My vessel", person.getCn()[0]);
        assertEquals("DK", person.getPostalAddress());
        assertEquals(1, person.getAuthorities().size());
        assertEquals("ROLE_ROUTEPLANNER", person.getAuthorities().iterator().next().getAuthority());
    }
}
