/*
 * Copyright 2017 Danish Maritime Authority.
 * Copyright 2020 Maritime Connectivity Platform Consortium
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

import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenAPIConfig {

    @Value("${net.maritimeconnectivity.idreg.openapi.oidc-base-path}")
    private String oidcBasePath;
    @Value("${net.maritimeconnectivity.idreg.openapi.x509-base-path}")
    private String x509BasePath;

    @Bean
    public GroupedOpenApi oidcApi() {
        return GroupedOpenApi.builder()
                .group("mcp-idreg-oidc")
                .pathsToMatch("/oidc/api/**")
                .build();
    }

    @Bean
    public GroupedOpenApi x509Api() {
        return GroupedOpenApi.builder()
                .group("mcp-idreg-x509")
                .pathsToMatch("/x509/api/**")
                .build();
    }

    @Bean
    public GroupedOpenApi secomApi() {
        return GroupedOpenApi.builder()
                .group("mcp-idreg-secom")
                .pathsToMatch("/secom/v1/**")
                .build();
    }

    @Bean
    public OpenAPI mirOpenAPI() {
        String v3ApiDocs = "/v3/api-docs/";
        oidcBasePath = oidcBasePath.strip();
        while (oidcBasePath.endsWith("/"))
            oidcBasePath = oidcBasePath.substring(0, oidcBasePath.length() - 1);
        String oidcUrl = oidcBasePath + v3ApiDocs + oidcApi().getGroup();
        x509BasePath = x509BasePath.strip();
        while (x509BasePath.endsWith("/"))
            x509BasePath = x509BasePath.substring(0, x509BasePath.length() - 1);
        String x509Url = x509BasePath + v3ApiDocs + x509Api().getGroup();
        String secomUrl = oidcBasePath + v3ApiDocs + secomApi().getGroup();

        return new OpenAPI()
                .info(new Info().title("Maritime Connectivity Platform Identity Registry API")
                        .description(String.format("The MCP Identity Registry API can be used for managing entities in the Maritime Connectivity Platform.<br>" +
                                "Two versions of the API are available - one that requires authentication using OpenID Connect and one that requires authentication using a X.509 client certificate.<br>" +
                                "The OpenAPI descriptions for the two versions are available <a href=\"%s\">here</a> and <a href=\"%s\">here</a>.<br>" +
                                "Additionally, a SECOM based API is also available for which the OpenAPI description can be found <a href=\"%s\">here</a>.", oidcUrl, x509Url, secomUrl))
                        .version("1.3.2")
                        .contact(new Contact().name("Maritime Connectivity Platform").url("https://maritimeconnectivity.net").email("info@maritimeconnectivity.net"))
                        .license(new License().name("Apache 2.0").url("https://www.apache.org/licenses/LICENSE-2.0")))
                .externalDocs(new ExternalDocumentation()
                        .description("MCP Identity Registry docs")
                        .url("https://docs.maritimeconnectivity.net/en/latest/MIR.html"));
    }

}
