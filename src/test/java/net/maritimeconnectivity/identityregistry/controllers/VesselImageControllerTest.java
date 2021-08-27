/*
 * Copyright 2017 Danish Maritime Authority
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

import com.google.common.collect.Lists;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.model.database.VesselImage;
import net.maritimeconnectivity.identityregistry.model.database.entities.Vessel;
import net.maritimeconnectivity.identityregistry.repositories.OrganizationRepository;
import net.maritimeconnectivity.identityregistry.repositories.VesselRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.util.AssertionErrors.assertEquals;
import static org.springframework.test.util.AssertionErrors.assertNull;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@ContextConfiguration
class VesselImageControllerTest {

    @Autowired
    VesselImageController vesselImageController;

    @Autowired
    OrganizationRepository orgRepo;

    @Autowired
    VesselRepository vesselRepo;

    @Autowired
    EntityManagerFactory emf;

    @Test
    void deleteImage() throws Exception {
        assertNumberOfImages(0);

        Organization org = new Organization();
        org.setMrn("urn:mrn:mcp:org:idp1:dma");
        org.setAddress("Carl Jakobsensvej 31, 2500 Valby");
        org.setCountry("Denmark");
        org.setUrl("http://dma.dk");
        org.setEmail("dma@dma.dk");
        org.setName("Danish Maritime Authority");
        org.setApproved(true);
        org.setFederationType("external-idp");
        org.setCertificateAuthority("TEST_CA");

        orgRepo.save(org);

        Vessel vessel = new Vessel();
        vessel.setIdOrganization(org.getId());
        vessel.setMrn("urn:mrn:mcp:vessel:idp1:dma:poul-loewnoern");
        vessel.setName("POUL LØWENØRN");
        VesselImage image = new VesselImage();
        image.setImage(new byte[]{1, 2, 3});
        vessel.setImage(image);

        vesselRepo.save(vessel);

        // fiddle with security to be able to call the delete method
        InetOrgPerson person = mock(InetOrgPerson.class);
        when(person.getO()).then(invocation -> org.getMrn());
        Authentication previousAuth = SecurityContextHolder.getContext().getAuthentication();
        SecurityContextHolder.getContext().setAuthentication(new PreAuthenticatedAuthenticationToken(person, "",
                Lists.newArrayList(new SimpleGrantedAuthority("ROLE_ORG_ADMIN"))));

        try {
            vesselImageController.deleteVesselImage(new MockHttpServletRequest("DELETE", "/path"), org.getMrn(), vessel.getMrn());

            Vessel reloaded = vesselRepo.getByMrnIgnoreCase(vessel.getMrn());
            assertNull("Image should be deleted", reloaded.getImage());

            assertNumberOfImages(0);
        } finally {
            SecurityContextHolder.getContext().setAuthentication(previousAuth);
        }
    }

    private void assertNumberOfImages(int expectedImageCount) {
        EntityManager em = emf.createEntityManager();
        try {
            List<VesselImage> images = em.createQuery("select i from VesselImage i", VesselImage.class).getResultList();
            assertEquals("Number of images", expectedImageCount, images.size());
        } catch (Exception e) {
            em.close();
        }
    }
}
