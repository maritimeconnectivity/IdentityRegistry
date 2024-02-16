/*
 * Copyright 2024 Maritime Connectivity Platform Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.maritimeconnectivity.identityregistry.controllers;

import net.maritimeconnectivity.identityregistry.model.database.Certificate;
import net.maritimeconnectivity.identityregistry.model.database.entities.Service;
import net.maritimeconnectivity.identityregistry.services.CertificateService;
import net.maritimeconnectivity.identityregistry.services.ServiceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@ContextConfiguration
@WebAppConfiguration
@ActiveProfiles("test")
class SecomControllerTests {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mvc;

    @MockBean
    private CertificateService certificateService;

    @MockBean
    private ServiceService serviceService;

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    @Test
    void testGetPublicKeyBySerialNumber() {
        Certificate certificate = new Certificate();
        try {
            String pemCrt = getCertificate("src/test/resources/Certificate_Myboat.pem");
            certificate.setCertificate(pemCrt);
            certificate.setSerialNumber(BigInteger.valueOf(9001));
            certificate.setStart(new Date());
            Calendar calendar = new GregorianCalendar();
            calendar.add(Calendar.MONTH, 6);
            certificate.setEnd(calendar.getTime());
            given(this.certificateService.getCertificateBySerialNumber(certificate.getSerialNumber())).willReturn(certificate);

            MvcResult result = mvc.perform(get("/secom/v1/publicKey/9001"))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith("application/x-pem-file"))
                    .andReturn();
            String resultBody = result.getResponse().getContentAsString();
            assertEquals(pemCrt, resultBody);
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testGetPublicKeyBySerialNumberNotExisting() {
        Certificate certificate = new Certificate();
        try {
            String pemCrt = getCertificate("src/test/resources/Certificate_Myboat.pem");
            certificate.setCertificate(pemCrt);
            certificate.setSerialNumber(BigInteger.valueOf(9001));
            certificate.setStart(new Date());
            Calendar calendar = new GregorianCalendar();
            calendar.add(Calendar.MONTH, 6);
            certificate.setEnd(calendar.getTime());

            mvc.perform(get("/secom/v1/publicKey/9002"))
                    .andExpect(status().isNotFound());
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testGetPublicKeyByThumbprint() {
        Certificate certificate = new Certificate();
        try {
            String pemCrt = getCertificate("src/test/resources/Certificate_Myboat.pem");
            certificate.setCertificate(pemCrt);
            certificate.setThumbprint("SCcX8Em7DfIPgnudKsJdKOPGeO1kNV0ICR7lGr2sqZw=");
            certificate.setStart(new Date());
            Calendar calendar = new GregorianCalendar();
            calendar.add(Calendar.MONTH, 6);
            certificate.setEnd(calendar.getTime());
            given(this.certificateService.getCertificateByThumbprint(certificate.getThumbprint())).willReturn(certificate);

            MvcResult result = mvc.perform(get("/secom/v1/publicKey/SCcX8Em7DfIPgnudKsJdKOPGeO1kNV0ICR7lGr2sqZw="))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith("application/x-pem-file"))
                    .andReturn();
            String resultBody = result.getResponse().getContentAsString();
            assertEquals(pemCrt, resultBody);
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testGetPublicKeyByThumbprintNotExisting() {
        Certificate certificate = new Certificate();
        try {
            String pemCrt = getCertificate("src/test/resources/Certificate_Myboat.pem");
            certificate.setCertificate(pemCrt);
            certificate.setThumbprint("SCcX8Em7DfIPgnudKsJdKOPGeO1kNV0ICR7lGr2sqZw=");
            certificate.setStart(new Date());
            Calendar calendar = new GregorianCalendar();
            calendar.add(Calendar.MONTH, 6);
            certificate.setEnd(calendar.getTime());
            given(this.certificateService.getCertificateByThumbprint(certificate.getThumbprint())).willReturn(certificate);

            mvc.perform(get("/secom/v1/publicKey/PlQSr1T70aXKRbWZ026ZIIHTfcqyrOnst8HmXF+uDpA="))
                    .andExpect(status().isNotFound());
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testGetPublicKeyByMrn() throws IOException {
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:org1:srvc:1.0");
        String cert1 = getCertificate("src/test/resources/Certificate_Myboat.pem");
        String cert2 = getCertificate("src/test/resources/Certificate_Myservice.pem");
        Certificate c1 = new Certificate();
        c1.setCertificate(cert1);
        Calendar calendar = new GregorianCalendar();
        calendar.add(Calendar.DAY_OF_YEAR, -2); // 2 days ago
        c1.setStart(calendar.getTime());
        calendar = new GregorianCalendar();
        calendar.add(Calendar.MONTH, 6);
        c1.setEnd(calendar.getTime());
        Certificate c2 = new Certificate();
        c2.setCertificate(cert2);
        c2.setStart(new Date());
        c2.setEnd(calendar.getTime());
        service.setCertificates(Set.of(c1, c2));
        given(serviceService.getByMrn(service.getMrn())).willReturn(service);
        try {
            MvcResult result = mvc.perform(get("/secom/v1/publicKey/urn:mrn:mcp:service:idp1:org1:srvc:1.0"))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith("application/x-pem-file"))
                    .andReturn();
            String expected = cert2 + cert1;
            String resultBody = result.getResponse().getContentAsString();
            assertEquals(expected, resultBody);
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testGetPublicKeyByMrnWithOneExpiredCert() throws IOException {
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:org1:srvc:1.0");
        String cert1 = getCertificate("src/test/resources/Certificate_Myboat.pem");
        String cert2 = getCertificate("src/test/resources/Certificate_Myservice.pem");
        Certificate c1 = new Certificate();
        c1.setCertificate(cert1);
        Calendar calendar = new GregorianCalendar();
        calendar.add(Calendar.MONTH, -6); // 6 months ago
        c1.setStart(calendar.getTime());
        calendar = new GregorianCalendar();
        calendar.add(Calendar.DAY_OF_YEAR, -1); // yesterday
        c1.setEnd(calendar.getTime());
        Certificate c2 = new Certificate();
        c2.setCertificate(cert2);
        c2.setStart(new Date());
        calendar = new GregorianCalendar();
        calendar.add(Calendar.MONTH, 6);
        c2.setEnd(calendar.getTime());
        service.setCertificates(Set.of(c1, c2));
        given(serviceService.getByMrn(service.getMrn())).willReturn(service);
        try {
            MvcResult result = mvc.perform(get("/secom/v1/publicKey/urn:mrn:mcp:service:idp1:org1:srvc:1.0"))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith("application/x-pem-file"))
                    .andReturn();
            String resultBody = result.getResponse().getContentAsString();
            assertEquals(cert2, resultBody);
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testGetPublicKeyByMrnWithNoCerts() {
        Service service = new Service();
        service.setMrn("urn:mrn:mcp:service:idp1:org1:srvc:1.0");
        service.setCertificates(new HashSet<>());
        given(serviceService.getByMrn(service.getMrn())).willReturn(service);
        try {
            mvc.perform(get("/secom/v1/publicKey/urn:mrn:mcp:service:idp1:org1:srvc:1.0"))
                    .andExpect(status().isNotFound());
        } catch (Exception e) {
            fail(e);
        }
    }

    private String getCertificate(String path) throws IOException {
        return new String(Files.readAllBytes(new File(path).toPath()));
    }
}
