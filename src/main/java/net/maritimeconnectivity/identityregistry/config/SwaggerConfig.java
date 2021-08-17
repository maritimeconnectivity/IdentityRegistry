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
package net.maritimeconnectivity.identityregistry.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springdoc.core.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Bean
    public GroupedOpenApi api() {
        return GroupedOpenApi.builder()
                .group("mcp-idreg")
                .pathsToMatch("/oidc/api/**", "/x509/api/**")
                .build();
    }

    @Bean
    public OpenAPI mirOpenAPI() {
        return new OpenAPI()
                .info(new Info().title("Maritime Connectivity Platform Identity Registry API")
                        .description("The MCP Identity Registry API can be used for managing entities in the Maritime Connectivity Platform.")
                        .version("1.0.0")
                        .contact(new Contact().name("Maritime Connectivity Platform").url("https://maritimeconnectivity.net").email("info@maritimeconnectivity.net"))
                        .license(new License().name("Apache 2.0").url("https://www.apache.org/licenses/LICENSE-2.0")));
    }

}
