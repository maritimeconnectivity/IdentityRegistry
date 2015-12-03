/* Copyright 2015 Danish Maritime Authority.
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
package net.maritimecloud.identityregistry.security;

import java.util.Map;
import java.util.HashMap;
import java.util.HashSet;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.mitre.openid.connect.client.OIDCAuthenticationProvider;
import org.mitre.openid.connect.client.OIDCAuthenticationFilter;
import org.mitre.openid.connect.client.service.impl.StaticSingleIssuerService;
import org.mitre.openid.connect.client.service.impl.DynamicServerConfigurationService;
import org.mitre.openid.connect.client.service.impl.StaticClientConfigurationService;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.mitre.oauth2.model.RegisteredClient;
import org.mitre.openid.connect.client.service.impl.PlainAuthRequestUrlBuilder;
import org.mitre.openid.connect.client.service.impl.JsonFileRegisteredClientService;

@Configuration
@EnableWebSecurity
public class MultiSecurityConfig  {

    @Configuration
    @Order(2)
    public static class AdminWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        DataSource dataSource;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
        	System.out.println("Configuring Admin");
            http
                .csrf().disable()
                .authorizeRequests()
                    .antMatchers(HttpMethod.POST, "/admin/api/org/apply").permitAll()
                    .antMatchers(HttpMethod.POST, "/admin/api/**").authenticated()
                    .antMatchers(HttpMethod.PUT, "/admin/api/**").authenticated()
                    .antMatchers(HttpMethod.DELETE, "/admin/api/**").authenticated()
                    .antMatchers(HttpMethod.GET, "/admin/api/**").authenticated()
                    //.anyRequest().denyAll()
                .and()
                    .formLogin()
                        // This will make a successful login return HTTP 200
                        .successHandler(new RestAuthenticationSuccessHandler())
                        // This will make a failed login return HTTP 401 (because a failed redirect url isn't given)
                        .failureHandler(new SimpleUrlAuthenticationFailureHandler())
                        .permitAll()
                .and()
                    .logout().permitAll()
            ;
        }

        @Autowired
        public void configAuthentication(AuthenticationManagerBuilder auth) throws Exception {

            auth.jdbcAuthentication().dataSource(dataSource)
                    .usersByUsernameQuery("SELECT short_name, password_hash, 1 FROM organizations WHERE short_name=?")
                    .passwordEncoder(new BCryptPasswordEncoder())
                    .authoritiesByUsernameQuery("SELECT ?, 'ROLE_ADMIN' FROM DUAL")
            //.authoritiesByUsernameQuery( "select username, role from user_roles where username=?")
            ;
        }
    }

    @Configuration
    @Order(1)
    public static class OIDCWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
    	
        protected void configure(HttpSecurity http) throws Exception {
        	System.out.println("Configuring OIDC");
        	String issuerUrl = "http://localhost:9080/auth/realms/master";
        	OIDCAuthenticationProvider oidcAuthenticationProvider = new OIDCAuthenticationProvider();
        	// Create a Filter to setup OIDC
        	OIDCAuthenticationFilter oidcFilter = new OIDCAuthenticationFilter();
        	// Connect an issuer
        	StaticSingleIssuerService issuerService = new StaticSingleIssuerService();
        	issuerService.setIssuer(issuerUrl); // From keycloak
        	oidcFilter.setIssuerService(issuerService);
        	// Using DynamicServerConfigurationService should mean that it fetches the config
        	// directly from issuer + "/.well-known/openid-configuration"
        	oidcFilter.setServerConfigurationService(new DynamicServerConfigurationService());
        	// Configure client, uses static conf, meaning only one issuer
        	StaticClientConfigurationService clientConf = new StaticClientConfigurationService();
        	// Fetch client (keycloak) setup from file
        	JsonFileRegisteredClientService jsonRegClient = new JsonFileRegisteredClientService("setup/keycloak-client.json");
        	Map<String, RegisteredClient> clientsMap = new HashMap<String, RegisteredClient>();
        	clientsMap.put(issuerUrl, jsonRegClient.getByIssuer(issuerUrl));
        	clientConf.setClients(clientsMap);
        	oidcFilter.setClientConfigurationService(clientConf);
        	oidcFilter.setAuthRequestUrlBuilder(new PlainAuthRequestUrlBuilder());
        	
        	http
        		//.antMatcher("/oidc/**")
                .csrf().disable()
                .authorizeRequests()
                    .antMatchers(HttpMethod.POST, "/oidc/api/**").authenticated()
                    .antMatchers(HttpMethod.PUT, "/oidc/api/**").authenticated()
                    .antMatchers(HttpMethod.DELETE, "/oidc/api/**").authenticated()
                    .antMatchers(HttpMethod.GET, "/oidc/api/**").authenticated()
                    //.anyRequest().denyAll()
                .and()
                    .authenticationProvider(oidcAuthenticationProvider)
                .addFilterBefore(oidcFilter, BasicAuthenticationFilter.class)
                .exceptionHandling().authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/openid_connect_login"))
            ;
        }

    }

    // See https://docs.spring.io/spring-security/site/docs/4.0.x/reference/html/x509.html
    // Needs some work to actually work!!
    @Configuration
    @Order(3)
    public static class X509WebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
        protected void configure(HttpSecurity http) throws Exception {
        	System.out.println("Configuring X509");
            http
            	.antMatcher("/x509/**")
                .csrf().disable()
                .authorizeRequests()
                    .antMatchers(HttpMethod.POST, "/x509/api/**").authenticated()
                    .antMatchers(HttpMethod.PUT, "/x509/api/**").authenticated()
                    .antMatchers(HttpMethod.DELETE, "/x509/api/**").authenticated()
                    .antMatchers(HttpMethod.GET, "/x509/api/**").authenticated()
                    //.anyRequest().denyAll()
                .and()
                    .x509()
                        .subjectPrincipalRegex("CN=(.*?),")
            ;
        }

    }
}
