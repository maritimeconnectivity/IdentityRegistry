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

import net.maritimeconnectivity.identityregistry.model.database.Certificate;
import net.maritimeconnectivity.identityregistry.repositories.CertificateRepository;
import net.maritimeconnectivity.identityregistry.services.CertificateService;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.util.encoders.DecoderException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.doReturn;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@ContextConfiguration
@WebAppConfiguration
@ActiveProfiles("test")
class CertificateControllerTests {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mvc;

    @MockBean
    CertificateService certificateService;

    @MockBean
    CertificateRepository certificateRepository;

    @MockBean
    JwtDecoder jwtDecoder;

    @InjectMocks
    CertificateController certificateController;

    @BeforeEach
    void setup() {
        this.certificateController = Mockito.spy(CertificateController.class);
        mvc = MockMvcBuilders.webAppContextSetup(context).build();
    }

    @Test
    void testGetOSCP() {
        String boatCert = null;
        try {
            boatCert = Files.readString(Path.of("src/test/resources/Certificate_Myboat.pem"));
        } catch (IOException e) {
            fail("Could not cert from file", e);
        }
        Certificate certificate = new Certificate();
        certificate.setCertificate(boatCert);
        certificate.setCertificateAuthority("urn:mrn:mcp:ca:idp1:mcp-idreg");
        certificate.setSerialNumber(new BigInteger("347551699453548165462610319955258467284009693116"));
        doReturn(certificate).when(certificateService).getCertificateBySerialNumber(certificate.getSerialNumber());

        try {
            MvcResult result = mvc.perform(get(new URI("/x509/api/certificates/ocsp/urn:mrn:mcp:ca:idp1:mcp-idreg/MHoweDBRME8wTTAJBgUrDgMCGgUABBS7OosoO9MtHNXNnnX28SnBklXcmQQU0OaAYMyxB3t43CCu%0A70%2BPjaPwIkACFDzgwdhQ2iH9aLmnBOPrlLmG4S%2B8oiMwITAfBgkrBgEFBQcwAQIEEgQQjCuQ1bAT%0AD%2B4aIlqkc4vQEw%3D%3D")).header("Origin", "bla"))
                    .andExpect(status().isOk()).andReturn();
            OCSPResp ocspResp = new OCSPResp(result.getResponse().getContentAsByteArray());
            assertEquals(OCSPResp.SUCCESSFUL, ocspResp.getStatus());
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testGetOSCPInvalid() {
        try {
            // The encoded OCSP request is missing some chars at the end and is therefore invalid
            mvc.perform(get("/x509/api/certificates/ocsp/urn:mrn:mcp:ca:maritimecloud-idreg/MFUwUzBRME8wTTAJBgUrDgMCGgUABBQ6UIqQ34%2BgN2srrAjL6PckJ0ELZQQUxE5nZxstKKPxT9ruhJjPzxpwfFUCFCPUaD%2Fh4aw7GY%2F7bjSdgGf").header("Origin", "bla"));
            fail("This shold not be reached, an exception should be thrown!");
        } catch (Exception e) {
            assertTrue(e.getCause() instanceof DecoderException);
        }
    }

    @Test
    void testGetCertificateChainByThumbprint() {
        String boatCert = null;
        String certChain = null;
        try {
            boatCert = Files.readString(Path.of("src/test/resources/Certificate_Myboat.pem"));
            certChain = Files.readString(Path.of("src/test/resources/certchain.pem"));
        } catch (IOException e) {
            fail("Could not read certificate from file", e);
        }
        Certificate certificate = new Certificate();
        certificate.setCertificate(boatCert);
        certificate.setCertificateAuthority("urn:mrn:mcp:ca:idp1:mcp-idreg");
        certificate.setSerialNumber(new BigInteger("347551699453548165462610319955258467284009693116"));
        doReturn(certificate).when(certificateService).getCertificateBySerialNumber(certificate.getSerialNumber());

        try {
            MvcResult result = mvc.perform(get("/x509/api/certificates/certchain/" + certificate.getSerialNumber())).andReturn();
            assertEquals(certChain, result.getResponse().getContentAsString());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
