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
package net.maritimeconnectivity.identityregistry.security;

import net.maritimeconnectivity.identityregistry.config.SimpleCorsFilter;
import net.maritimeconnectivity.identityregistry.security.x509.X509HeaderUserDetailsService;
import net.maritimeconnectivity.identityregistry.security.x509.X509UserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;
import org.springframework.security.web.firewall.DefaultHttpFirewall;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class MultiSecurityConfig {

    @Bean
    public static RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        // If the hierarchy is changed, remember to update the hierarchy above and the list in
        // net.maritimeconnectivity.identityregistry.controllers.RoleController:getAvailableRoles()
        roleHierarchy.setHierarchy("""
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
        return roleHierarchy;
    }

    @Bean
    public static GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
        return new RoleHierarchyAuthoritiesMapper(roleHierarchy());
    }

    @Bean
    public static MethodSecurityExpressionHandler webExpressionHandler() {
        DefaultMethodSecurityExpressionHandler defaultMethodSecurityExpressionHandler = new DefaultMethodSecurityExpressionHandler();
        defaultMethodSecurityExpressionHandler.setRoleHierarchy(roleHierarchy());
        return defaultMethodSecurityExpressionHandler;
    }

    @Bean
    protected WebSecurityCustomizer webSecurityCustomizer() {
        // Allow URL encoded slashes in URL. Needed for OCSP. Only needed for X509, since that is where the OCSP endpoint is
        return webSecurity -> {
            DefaultHttpFirewall firewall = new DefaultHttpFirewall();
            firewall.setAllowUrlEncodedSlash(true);
            webSecurity.httpFirewall(firewall);
        };
    }

    @Bean
    protected FilterChainProxy filterChainProxy(List<SecurityFilterChain> filterChains) {
        return new FilterChainProxy(filterChains);
    }

    @Configuration
    @Order(1)
    public static class OIDCWebSecurityConfigurationAdapter {
        /**
         * Registers the MCKeycloakAuthenticationProvider with the authentication manager.
         */
        @Autowired
        public void configureGlobal(AuthenticationManagerBuilder auth, MCPKeycloakAuthenticationProvider mcpKeycloakAuthenticationProvider) {
            auth.authenticationProvider(mcpKeycloakAuthenticationProvider);
        }

        @Bean(name = "oidcChain")
        protected SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManagerBuilder authenticationManagerBuilder, MCPKeycloakAuthenticationProvider authenticationProvider) throws Exception {
            http
                    .addFilterBefore(new SimpleCorsFilter(), ChannelProcessingFilter.class)
                    .csrf().disable()
                    .authorizeHttpRequests(authz -> authz
                            .requestMatchers(HttpMethod.POST, "/oidc/api/report-bug").permitAll()
                            .requestMatchers(HttpMethod.POST, "/oidc/api/org/apply").permitAll()
                            .requestMatchers(HttpMethod.GET, "/oidc/api/certificates/crl/*").permitAll()
                            .requestMatchers(HttpMethod.GET, "/oidc/api/certificates/ocsp/**").permitAll()
                            .requestMatchers(HttpMethod.POST, "/oidc/api/certificates/ocsp/*").permitAll()
                            .requestMatchers(HttpMethod.POST, "/oidc/api/**").authenticated()
                            .requestMatchers(HttpMethod.PUT, "/oidc/api/**").authenticated()
                            .requestMatchers(HttpMethod.DELETE, "/oidc/api/**").authenticated()
                            .requestMatchers(HttpMethod.GET, "/oidc/api/**").authenticated()
                            .requestMatchers(HttpMethod.GET, "/service/**").denyAll())
                    .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

            authenticationManagerBuilder.authenticationProvider(authenticationProvider);
            http.authenticationManager(authenticationManagerBuilder.getOrBuild());
            return http.build();
        }
    }

    // See https://docs.spring.io/spring-security/reference/servlet/authentication/x509.html
    @Configuration
    @Order(2)
    public static class X509WebSecurityConfigurationAdapter {

        @Value("${server.ssl.enabled:false}")
        private boolean useStandardSSL;

        @Bean(name = "x509Chain")
        protected SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
            http
                    .authorizeHttpRequests(authz -> authz
                            .requestMatchers(HttpMethod.POST, "/x509/api/report-bug").permitAll()
                            .requestMatchers(HttpMethod.POST, "/x509/api/org/apply").permitAll()
                            .requestMatchers(HttpMethod.GET, "/x509/api/certificates/crl/*").permitAll()
                            .requestMatchers(HttpMethod.GET, "/x509/api/certificates/ocsp/**").permitAll()
                            .requestMatchers(HttpMethod.POST, "/x509/api/certificates/ocsp/*").permitAll()
                            .requestMatchers(HttpMethod.POST, "/x509/api/**").authenticated()
                            .requestMatchers(HttpMethod.PUT, "/x509/api/**").authenticated()
                            .requestMatchers(HttpMethod.DELETE, "/x509/api/**").authenticated()
                            .requestMatchers(HttpMethod.GET, "/x509/api/**").authenticated()
                            .requestMatchers(HttpMethod.GET, "/service/**").authenticated());

            if (!useStandardSSL) {
                X509HeaderUserDetailsService userDetailsService = new X509HeaderUserDetailsService();
                UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> wrapper = new UserDetailsByNameServiceWrapper<>(userDetailsService);
                PreAuthenticatedAuthenticationProvider preAuthenticatedAuthenticationProvider = new PreAuthenticatedAuthenticationProvider();
                preAuthenticatedAuthenticationProvider.setPreAuthenticatedUserDetailsService(wrapper);
                authenticationManagerBuilder.authenticationProvider(preAuthenticatedAuthenticationProvider);
                // Create and setup the filter used to extract the client certificate from the header
                RequestHeaderAuthenticationFilter certFilter = new RequestHeaderAuthenticationFilter();
                certFilter.setAuthenticationManager(authenticationManagerBuilder.getOrBuild());
                certFilter.setPrincipalRequestHeader("X-Client-Certificate");
                certFilter.setExceptionIfHeaderMissing(false);
                http.addFilter(certFilter);
            } else {
                // Using this approach is not recommended since we don't extract all the information from
                // the certificate, as done in the approach above.
                http
                        .x509()
                        .subjectPrincipalRegex("(.*)") // Extract all and let it be handled by the X509UserDetailsService. "CN=(.*?)," for CommonName only
                        .userDetailsService(new X509UserDetailsService());
            }
            return http.build();
        }
    }
}
