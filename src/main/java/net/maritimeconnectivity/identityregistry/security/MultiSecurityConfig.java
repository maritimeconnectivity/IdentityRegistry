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
package net.maritimeconnectivity.identityregistry.security;

import net.maritimeconnectivity.identityregistry.config.SimpleCorsFilter;
import net.maritimeconnectivity.identityregistry.security.x509.X509HeaderUserDetailsService;
import net.maritimeconnectivity.identityregistry.security.x509.X509UserDetailsService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyAuthoritiesMapper;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;
import org.springframework.security.web.firewall.DefaultHttpFirewall;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class MultiSecurityConfig {

    @Value("${server.ssl.enabled:false}")
    private boolean useStandardSSL;

    @Value("${net.maritimeconnectivity.idreg.certs.client-cert-header:X-Client-Certificate}")
    private String clientCertHeader;

    @Bean
    public RoleHierarchy roleHierarchy() {
        // If the hierarchy is changed, remember to update the hierarchy above and the list in
        // net.maritimeconnectivity.identityregistry.controllers.RoleController:getAvailableRoles()
        return RoleHierarchyImpl.fromHierarchy("""
                ROLE_SITE_ADMIN > ROLE_APPROVE_ORG
                ROLE_SITE_ADMIN > ROLE_ORG_ADMIN
                ROLE_ORG_ADMIN > ROLE_ENTITY_ADMIN
                ROLE_ENTITY_ADMIN > ROLE_USER_ADMIN
                ROLE_ENTITY_ADMIN > ROLE_VESSEL_ADMIN
                ROLE_ENTITY_ADMIN > ROLE_SERVICE_ADMIN
                ROLE_ENTITY_ADMIN > ROLE_DEVICE_ADMIN
                ROLE_ENTITY_ADMIN > ROLE_MMS_ADMIN
                ROLE_USER_ADMIN > ROLE_USER
                ROLE_VESSEL_ADMIN > ROLE_USER
                ROLE_SERVICE_ADMIN > ROLE_USER
                ROLE_DEVICE_ADMIN > ROLE_USER""");
    }

    @Bean
    public GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
        return new RoleHierarchyAuthoritiesMapper(roleHierarchy());
    }

    @Bean
    public MethodSecurityExpressionHandler webExpressionHandler() {
        DefaultMethodSecurityExpressionHandler defaultMethodSecurityExpressionHandler = new DefaultMethodSecurityExpressionHandler();
        defaultMethodSecurityExpressionHandler.setRoleHierarchy(roleHierarchy());
        return defaultMethodSecurityExpressionHandler;
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        // Allow URL encoded slashes in URL. Needed for OCSP.
        return webSecurity -> {
            DefaultHttpFirewall firewall = new DefaultHttpFirewall();
            firewall.setAllowUrlEncodedSlash(true);
            webSecurity.httpFirewall(firewall);
        };
    }

    @Bean
    public JwtAuthenticationConverter customAuthenticationConverter(McpJwtGrantedAuthoritiesConverter mcpJwtGrantedAuthoritiesConverter) {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(mcpJwtGrantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain oidcFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/oidc/**", "/v3/api-docs", "/v3/api-docs/**")
                .addFilterBefore(new SimpleCorsFilter(), ChannelProcessingFilter.class)
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(HttpMethod.POST, "/oidc/api/report-bug").permitAll()
                        .requestMatchers(HttpMethod.POST, "/oidc/api/org/apply").permitAll()
                        .requestMatchers(HttpMethod.GET, "/oidc/api/certificates/crl/*").permitAll()
                        .requestMatchers(HttpMethod.GET, "/oidc/api/certificates/ocsp/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/oidc/api/certificates/ocsp/*").permitAll()
                        .requestMatchers(HttpMethod.GET, "/v3/api-docs").permitAll()
                        .requestMatchers(HttpMethod.OPTIONS, "/v3/api-docs").permitAll()
                        .requestMatchers(HttpMethod.GET, "/v3/api-docs/**").permitAll()
                        .requestMatchers(HttpMethod.OPTIONS, "/v3/api-docs/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/swagger-ui/**").permitAll()
                        .requestMatchers(HttpMethod.OPTIONS, "/oidc/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/secom/v1/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/oidc/api/**").authenticated()
                        .requestMatchers(HttpMethod.PUT, "/oidc/api/**").authenticated()
                        .requestMatchers(HttpMethod.DELETE, "/oidc/api/**").authenticated()
                        .requestMatchers(HttpMethod.GET, "/oidc/api/**").authenticated()
                        .requestMatchers(HttpMethod.PATCH, "/oidc/api/**").authenticated()
                        .requestMatchers(HttpMethod.GET, "/service/**").denyAll())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain x509FilterChain(HttpSecurity http, X509HeaderUserDetailsService x509HeaderUserDetailsService) throws Exception {
        http
                .securityMatcher("/x509/**", "/service/**")
                .addFilterBefore(new SimpleCorsFilter(), ChannelProcessingFilter.class)
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(HttpMethod.POST, "/x509/api/report-bug").permitAll()
                        .requestMatchers(HttpMethod.POST, "/x509/api/org/apply").permitAll()
                        .requestMatchers(HttpMethod.GET, "/x509/api/certificates/crl/*").permitAll()
                        .requestMatchers(HttpMethod.GET, "/x509/api/certificates/ocsp/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/x509/api/certificates/ocsp/*").permitAll()
                        .requestMatchers(HttpMethod.GET, "/v3/api-docs").permitAll()
                        .requestMatchers(HttpMethod.OPTIONS, "/v3/api-docs").permitAll()
                        .requestMatchers(HttpMethod.GET, "/v3/api-docs/**").permitAll()
                        .requestMatchers(HttpMethod.OPTIONS, "/v3/api-docs/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/swagger-ui/**").permitAll()
                        .requestMatchers(HttpMethod.OPTIONS, "/x509/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/secom/v1/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/x509/api/**").authenticated()
                        .requestMatchers(HttpMethod.PUT, "/x509/api/**").authenticated()
                        .requestMatchers(HttpMethod.DELETE, "/x509/api/**").authenticated()
                        .requestMatchers(HttpMethod.GET, "/x509/api/**").authenticated()
                        .requestMatchers(HttpMethod.PATCH, "/x509/api/**").authenticated()
                        .requestMatchers(HttpMethod.GET, "/service/**").authenticated());

        if (!useStandardSSL) {
            UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> wrapper = new UserDetailsByNameServiceWrapper<>(x509HeaderUserDetailsService);
            PreAuthenticatedAuthenticationProvider preAuthenticatedAuthenticationProvider = new PreAuthenticatedAuthenticationProvider();
            preAuthenticatedAuthenticationProvider.setPreAuthenticatedUserDetailsService(wrapper);
            ProviderManager providerManager = new ProviderManager(preAuthenticatedAuthenticationProvider);
            // Create and setup the filter used to extract the client certificate from the header
            RequestHeaderAuthenticationFilter certFilter = new RequestHeaderAuthenticationFilter();
            certFilter.setAuthenticationManager(providerManager);
            certFilter.setPrincipalRequestHeader(clientCertHeader);
            certFilter.setExceptionIfHeaderMissing(false);
            http.addFilter(certFilter);
        } else {
            // Using this approach is not recommended since we don't extract all the information from
            // the certificate, as done in the approach above.
            http
                    .x509(x509 -> x509
                            .subjectPrincipalRegex("(.*)") // Extract all and let it be handled by the X509UserDetailsService. "CN=(.*?)," for CommonName only
                            .userDetailsService(new X509UserDetailsService()));
        }
        return http.build();
    }
}
