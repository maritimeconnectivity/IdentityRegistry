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

import net.maritimeconnectivity.identityregistry.utils.MCPIdRegConstants;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Helper class to generate fake tokens for use when testing controllers.
 */
class TokenGenerator {

    /**
     * Helper function of build fake JwtAuthenticationToken
     *
     * @param mrn
     * @param roles
     * @param permissions
     * @return
     */
    static JwtAuthenticationToken generateKeycloakToken(String mrn, String roles, String permissions) {
//        AccessToken accessToken = new AccessToken();
        Map<String, Object> claims = new HashMap<>();
        if (mrn != null && !mrn.isEmpty()) {
            claims.put(MCPIdRegConstants.MRN_PROPERTY_NAME, mrn);
        }
        if (permissions != null && !permissions.isEmpty()) {
            claims.put(MCPIdRegConstants.PERMISSIONS_PROPERTY_NAME, permissions);
        }
        String bearerTokenString = UUID.randomUUID().toString();

        Collection<GrantedAuthority> authorities = generateGrantedAuthority(roles);
        Jwt jwt = new Jwt(bearerTokenString, Instant.now(), Instant.now().plusSeconds(60), Map.of("alg", "none"), claims);
        return new JwtAuthenticationToken(jwt, authorities);
    }

    /**
     * Helper function of build fake PreAuthenticatedAuthenticationToken - used for x509 authentication
     * @param orgMrn
     * @param roles
     * @param permissions
     * @return
     */
    static PreAuthenticatedAuthenticationToken generatePreAuthenticatedAuthenticationToken(String orgMrn, String roles, String permissions) {
        Collection<GrantedAuthority> authorities = generateGrantedAuthority(roles);
        InetOrgPerson.Essence essence = new InetOrgPerson.Essence();
        String username = "urn:mrn:mcl:user:dma:dmauser";
        essence.setUsername(username);
        essence.setUid(username);
        essence.setDn("O="+orgMrn);
        essence.setO(orgMrn);
        essence.setCn(new String[] {"dmauser"});
        essence.setAuthorities(authorities);

        return new PreAuthenticatedAuthenticationToken(essence.createUserDetails(), null, authorities);
    }

    static Collection<GrantedAuthority> generateGrantedAuthority(String roles) {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        String[] roleArr = roles.split(",");
        for(String role : roleArr) {
            authorities.add(new SimpleGrantedAuthority(role.trim()));
        }
        return authorities;
    }
}
