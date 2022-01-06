/*
 * Copyright 2018 Danish Maritime Authority
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
package net.maritimeconnectivity.identityregistry.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springdoc.core.GroupedOpenApi;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@ContextConfiguration
@WebAppConfiguration
class OpenApiTests {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mvc;

    @Autowired
    private GroupedOpenApi oidcApi;

    @Autowired
    private GroupedOpenApi x509Api;

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    @Test
    void testOpenApiLoads() throws Exception {
        mvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk());
    }

    @Test
    void testOidcOpenApiLoads() throws Exception {
        mvc.perform(get("/v3/api-docs/" + oidcApi.getGroup()))
                .andExpect(status().isOk());
    }

    @Test
    void testX509OpenApiLoads() throws Exception {
        mvc.perform(get("/v3/api-docs/" + x509Api.getGroup()))
                .andExpect(status().isOk());
    }
}
