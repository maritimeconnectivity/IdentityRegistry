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
package net.maritimecloud.identityregistry.security.x509;

import net.maritimecloud.identityregistry.model.database.Organization;
import net.maritimecloud.identityregistry.model.database.Role;
import net.maritimecloud.identityregistry.services.OrganizationService;
import net.maritimecloud.identityregistry.services.RoleService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;

@RunWith(SpringJUnit4ClassRunner.class)
public class X509HeaderUserDetailsServiceTest {

    @MockBean
    private RoleService roleService;
    @MockBean
    private OrganizationService organizationService;

    @InjectMocks
    X509HeaderUserDetailsService x509HeaderUserDetailsService;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void loadUserByUsernameVessel1() throws Exception {
        // Load certificate from file
        String certFile = "src/test/resources/Certificate_Myboat.pem";
        String contents = null;
        try {
            contents = Files.lines(Paths.get(certFile)).collect(Collectors.joining("\n"));
        } catch (IOException e) {
            e.printStackTrace();
            fail("Loading Certificate from file failed!");
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

    @Test
    public void loadUserByUsernameVessel2() throws Exception {
        // Load certificate from file
        String certFile = "src/test/resources/Certificate_My_vessel.pem";
        String contents = null;
        try {
            contents = Files.lines(Paths.get(certFile)).collect(Collectors.joining("\n"));
        } catch (IOException e) {
            e.printStackTrace();
            fail("Loading Certificate from file failed!");
        }
        // Setup mocked role
        Role role = new Role();
        role.setPermission("routeplanner");
        role.setRoleName("ROLE_ROUTEPLANNER");
        given(this.roleService.getRolesByIdOrganizationAndPermission(any(Long.class), eq("routeplanner"))).willReturn(Arrays.asList(role));
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
