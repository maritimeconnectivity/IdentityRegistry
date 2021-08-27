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

import net.maritimeconnectivity.identityregistry.services.CertificateService;
import org.bouncycastle.util.encoders.DecoderException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@ContextConfiguration
@WebAppConfiguration
public class CertificateControllerTests {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mvc;

    @MockBean
    private CertificateService certificateService;

    @InjectMocks
    CertificateController certificateController;

    @BeforeEach
    public void setup() {
        this.certificateController = Mockito.spy(CertificateController.class);
        mvc = MockMvcBuilders.standaloneSetup(certificateController).build();
    }

    @Test
    public void testGetOSCP() {
        byte[] ret = "fake OCSP reply".getBytes(StandardCharsets.UTF_8);
        try {
            doReturn(ret).when(this.certificateController).handleOCSP(any(), any());
        } catch (IOException e) {
            fail(e);
            return;
        }

        try {
            mvc.perform(get(new URI("/x509/api/certificates/ocsp/urn:mrn:mcl:ca:maritimecloud-idreg/MFUwUzBRME8wTTAJBgUrDgMCGgUABBQ6UIqQ34%2BgN2srrAjL6PckJ0ELZQQUxE5nZxstKKPxT9ruhJjPzxpwfFUCFCPUaD%2Fh4aw7GY%2F7bjSdgGfC3pt2")).header("Origin", "bla"))
                    .andExpect(status().isOk()).andExpect(content().bytes(ret));
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    public void testGetOSCPInvalid() {
        try {
            // The encoded OCSP request is missing some chars at the end and is therefore invalid
            mvc.perform(get("/x509/api/certificates/ocsp/urn:mrn:mcl:ca:maritimecloud-idreg/MFUwUzBRME8wTTAJBgUrDgMCGgUABBQ6UIqQ34%2BgN2srrAjL6PckJ0ELZQQUxE5nZxstKKPxT9ruhJjPzxpwfFUCFCPUaD%2Fh4aw7GY%2F7bjSdgGf").header("Origin", "bla"));
            fail("This shold not be reached, an exception should be thrown!");
        } catch (Exception e) {
            assertTrue(e.getCause() instanceof DecoderException);
        }
    }

}
