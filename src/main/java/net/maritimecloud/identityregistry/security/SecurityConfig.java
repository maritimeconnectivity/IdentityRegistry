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

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	DataSource dataSource;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable()
			.authorizeRequests()
				.antMatchers(HttpMethod.POST, "/api/**").authenticated()
				.antMatchers(HttpMethod.PUT, "/api/**").authenticated()
				.antMatchers(HttpMethod.DELETE, "/api/**").authenticated()
				.antMatchers(HttpMethod.GET, "/api/**").authenticated()
				.anyRequest().permitAll()
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
		.usersByUsernameQuery(
			"SELECT short_name, password_hash, 1 FROM organizations WHERE short_name=?")
		.passwordEncoder(new BCryptPasswordEncoder())
		.authoritiesByUsernameQuery("SELECT ?, 'ROLE_ADMIN' FROM DUAL")
		/*.authoritiesByUsernameQuery(
			"select username, role from user_roles where username=?")*/
		;
	}	
}
