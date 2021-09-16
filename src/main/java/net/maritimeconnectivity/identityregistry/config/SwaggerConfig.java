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

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.oas.annotations.EnableOpenApi;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;

import java.math.BigInteger;

@Configuration
@EnableOpenApi
public class SwaggerConfig {

    @Bean
    public Docket api() { 
        return new Docket(DocumentationType.OAS_30)
          .apiInfo(getApiInfo())
          .directModelSubstitute(BigInteger.class, String.class)
            .forCodeGeneration(true)
          .select()
            .apis(RequestHandlerSelectors.any())
            .paths(PathSelectors.regex("/(oidc|x509)/api/.*"))
          .build();
    }

    private ApiInfo getApiInfo() {
        return new ApiInfoBuilder()
                .title("Maritime Connectivity Platform Identity Registry API")
                .description("The MCP Identity Registry API can be used for managing entities in the Maritime Connectivity Platform.")
                .version("0.12.2")
                .contact(new Contact("Maritime Connectivity Platform", "https://maritimeconnectivity.net", "info@maritimeconnectivity.net"))
                .license("Apache 2.0")
                .licenseUrl("https://www.apache.org/licenses/LICENSE-2.0")
                .build();
    }
}
