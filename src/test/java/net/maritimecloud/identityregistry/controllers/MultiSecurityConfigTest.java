package net.maritimecloud.identityregistry.controllers;

import net.maritimecloud.identityregistry.config.SimpleCorsFilter;
import net.maritimecloud.identityregistry.security.MCKeycloakAuthenticationProvider;
import net.maritimecloud.identityregistry.security.MultiSecurityConfig;
import net.maritimecloud.identityregistry.security.x509.X509HeaderUserDetailsService;
import net.maritimecloud.identityregistry.security.x509.X509UserDetailsService;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakPreAuthActionsFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.firewall.DefaultHttpFirewall;
import org.springframework.security.web.firewall.HttpFirewall;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Primary
public class MultiSecurityConfigTest {

    @Configuration
    @Order(1)
    @Primary
    public static class OIDCWebSecurityConfigurationAdapterTest extends KeycloakWebSecurityConfigurerAdapter
    {
        /**
         * Registers the MCKeycloakAuthenticationProvider with the authentication manager.
         */
        @Autowired
        public void configureGlobal(AuthenticationManagerBuilder auth) {
            auth.authenticationProvider(mcKeycloakAuthenticationProvider());
        }

        @Bean
        protected MCKeycloakAuthenticationProvider mcKeycloakAuthenticationProvider() {
            return new MCKeycloakAuthenticationProvider();
        }

        /**
         * Defines the session authentication strategy.
         */
        @Bean
        @Override
        protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
            // When using as confidential keycloak/OpenID Connect client:
            //return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
            // When using as bearer-only keycloak/OpenID Connect client:
            return new NullAuthenticatedSessionStrategy();
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception
        {
            http
                    .addFilterBefore(new SimpleCorsFilter(), ChannelProcessingFilter.class)
                    .csrf().disable()
                    .requestMatchers()
                    .antMatchers("/oidc/**","/sso/**") // "/sso/**" matches the urls used by the keycloak adapter
                    .and()
                    .authorizeRequests()
                    .expressionHandler(webExpressionHandler())
                    // Some general filters for access, more specific ones are set at each method
                    .antMatchers(HttpMethod.POST, "/oidc/api/report-bug").permitAll()
                    .antMatchers(HttpMethod.POST, "/oidc/api/org/apply").permitAll()
                    .antMatchers(HttpMethod.GET, "/oidc/api/certificates/crl/*").permitAll()
                    .antMatchers(HttpMethod.GET, "/oidc/api/certificates/ocsp/**").permitAll()
                    .antMatchers(HttpMethod.POST, "/oidc/api/certificates/ocsp/*").permitAll()
                    .antMatchers(HttpMethod.POST, "/oidc/api/**").authenticated()
                    .antMatchers(HttpMethod.PUT, "/oidc/api/**").authenticated()
                    .antMatchers(HttpMethod.DELETE, "/oidc/api/**").authenticated()
                    .antMatchers(HttpMethod.GET, "/oidc/api/**").authenticated()
                    .antMatchers(HttpMethod.GET, "/service/**").denyAll()
            ;
        }

        @Bean
        public FilterRegistrationBean keycloakAuthenticationProcessingFilterRegistrationBean(
                KeycloakAuthenticationProcessingFilter filter) {
            FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
            registrationBean.setEnabled(false);
            return registrationBean;
        }

        @Bean
        public FilterRegistrationBean keycloakPreAuthActionsFilterRegistrationBean(
                KeycloakPreAuthActionsFilter filter) {
            FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
            registrationBean.setEnabled(false);
            return registrationBean;
        }

        @Bean
        public RoleHierarchy roleHierarchy() {
            RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
            // If the hierarchy is changed, remember to update the hierarchy below and the list in
            // net.maritimecloud.identityregistry.controllers.RoleController:getAvailableRoles()
            roleHierarchy.setHierarchy("ROLE_SITE_ADMIN > ROLE_APPROVE_ORG\n" +
                    "ROLE_SITE_ADMIN > ROLE_ORG_ADMIN\n" +
                    "ROLE_ORG_ADMIN > ROLE_ENTITY_ADMIN\n" +
                    "ROLE_ENTITY_ADMIN > ROLE_USER_ADMIN\n" +
                    "ROLE_ENTITY_ADMIN > ROLE_VESSEL_ADMIN\n" +
                    "ROLE_ENTITY_ADMIN > ROLE_SERVICE_ADMIN\n" +
                    "ROLE_ENTITY_ADMIN > ROLE_DEVICE_ADMIN\n" +
                    "ROLE_USER_ADMIN > ROLE_USER\n" +
                    "ROLE_VESSEL_ADMIN > ROLE_USER\n" +
                    "ROLE_SERVICE_ADMIN > ROLE_USER\n" +
                    "ROLE_DEVICE_ADMIN > ROLE_USER");
            return roleHierarchy;
        }

        private SecurityExpressionHandler<FilterInvocation> webExpressionHandler() {
            DefaultWebSecurityExpressionHandler defaultWebSecurityExpressionHandler = new DefaultWebSecurityExpressionHandler();
            defaultWebSecurityExpressionHandler.setRoleHierarchy(roleHierarchy());
            return defaultWebSecurityExpressionHandler;
        }
    }

    // See https://docs.spring.io/spring-security/site/docs/4.0.x/reference/html/x509.html
    @Configuration
    @Order(2)
    @Primary
    public static class X509WebSecurityConfigurationAdapterTest extends WebSecurityConfigurerAdapter {

        @Value("${server.ssl.enabled:false}")
        private boolean useStandardSSL;
        private X509HeaderUserDetailsService userDetailsService;
        private PreAuthenticatedAuthenticationProvider preAuthenticatedProvider;

        public X509WebSecurityConfigurationAdapterTest() {
            super();
            if (!useStandardSSL) {
                userDetailsService = new X509HeaderUserDetailsService();
                UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> wrapper = new UserDetailsByNameServiceWrapper<>(userDetailsService);
                preAuthenticatedProvider = new PreAuthenticatedAuthenticationProvider();
                preAuthenticatedProvider.setPreAuthenticatedUserDetailsService(wrapper);
            }
        }

        @Override
        protected void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
            if (!useStandardSSL) {
                authenticationManagerBuilder.authenticationProvider(preAuthenticatedProvider);
            }
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .csrf().disable()
                    .authorizeRequests()
                    .expressionHandler(webExpressionHandler())
                    // Some general filters for access, more specific ones are set at each method
                    .antMatchers(HttpMethod.POST, "/x509/api/report-bug").permitAll()
                    .antMatchers(HttpMethod.POST, "/x509/api/org/apply").permitAll()
                    .antMatchers(HttpMethod.GET, "/x509/api/certificates/crl/*").permitAll()
                    .antMatchers(HttpMethod.GET, "/x509/api/certificates/ocsp/**").permitAll()
                    .antMatchers(HttpMethod.POST, "/x509/api/certificates/ocsp/*").permitAll()
                    .antMatchers(HttpMethod.POST, "/x509/api/**").authenticated()
                    .antMatchers(HttpMethod.PUT, "/x509/api/**").authenticated()
                    .antMatchers(HttpMethod.DELETE, "/x509/api/**").authenticated()
                    .antMatchers(HttpMethod.GET, "/x509/api/**").authenticated()
                    .antMatchers(HttpMethod.GET, "/service/**").authenticated()
            ;

            if (!useStandardSSL) {
                // Create and setup the filter used to extract the client certificate from the header
                RequestHeaderAuthenticationFilter certFilter = new RequestHeaderAuthenticationFilter();
                certFilter.setAuthenticationManager(authenticationManager());
                certFilter.setPrincipalRequestHeader("X-Client-Certificate");
                certFilter.setExceptionIfHeaderMissing(false);
                http.addFilter(certFilter);
            } else {
                // Using this approach is not recommended since we don't extract all the information from
                // the certificate, as done in the approach above.
                http
                        .x509()
                        .subjectPrincipalRegex("(.*)") // Extract all and let it be handled by the X509UserDetailsService. "CN=(.*?)," for CommonName only
                        .userDetailsService(x509UserDetailsService())
                ;
            }
        }

        @Bean
        public X509HeaderUserDetailsService x509HeaderUserDetailsService() {
            return userDetailsService;
        }

        @Bean
        public X509UserDetailsService x509UserDetailsService() {
            return new X509UserDetailsService();
        }

        @Bean
        public RoleHierarchy roleHierarchy() {
            RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
            // If the hierarchy is changed, remember to update the hierarchy above and the list in
            // net.maritimecloud.identityregistry.controllers.RoleController:getAvailableRoles()
            roleHierarchy.setHierarchy("ROLE_SITE_ADMIN > ROLE_APPROVE_ORG\n" +
                    "ROLE_SITE_ADMIN > ROLE_ORG_ADMIN\n" +
                    "ROLE_ORG_ADMIN > ROLE_ENTITY_ADMIN\n" +
                    "ROLE_ENTITY_ADMIN > ROLE_USER_ADMIN\n" +
                    "ROLE_ENTITY_ADMIN > ROLE_VESSEL_ADMIN\n" +
                    "ROLE_ENTITY_ADMIN > ROLE_SERVICE_ADMIN\n" +
                    "ROLE_ENTITY_ADMIN > ROLE_DEVICE_ADMIN\n" +
                    "ROLE_USER_ADMIN > ROLE_USER\n" +
                    "ROLE_VESSEL_ADMIN > ROLE_USER\n" +
                    "ROLE_SERVICE_ADMIN > ROLE_USER\n" +
                    "ROLE_DEVICE_ADMIN > ROLE_USER");
            return roleHierarchy;
        }

        private SecurityExpressionHandler<FilterInvocation> webExpressionHandler() {
            DefaultWebSecurityExpressionHandler defaultWebSecurityExpressionHandler = new DefaultWebSecurityExpressionHandler();
            defaultWebSecurityExpressionHandler.setRoleHierarchy(roleHierarchy());
            return defaultWebSecurityExpressionHandler;
        }

        // Allow URL encoded slashes in URL. Needed for OCSP. Only needed for X509, since that is where the OCSP endpoint is
        @Bean
        public HttpFirewall allowUrlEncodedSlashHttpFirewall() {
            DefaultHttpFirewall firewall = new DefaultHttpFirewall();
            firewall.setAllowUrlEncodedSlash(true);
            return firewall;
        }

        @Override
        public void configure(WebSecurity web) throws Exception {
            web.httpFirewall(allowUrlEncodedSlashHttpFirewall());
        }
    }
}
