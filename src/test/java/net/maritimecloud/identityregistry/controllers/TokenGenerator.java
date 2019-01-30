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

package net.maritimecloud.identityregistry.controllers;

import net.maritimecloud.identityregistry.utils.AccessControlUtil;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Helper class to generate fake tokens for use when testing controllers.
 */
public class TokenGenerator {

    /**
     * Helper function of build fake KeycloakAuthenticationToken
     * @param orgMrn
     * @param roles
     * @param permissions
     * @return
     */
    public static KeycloakAuthenticationToken generateKeycloakToken(String orgMrn, String roles, String permissions) {
        AccessToken accessToken = new AccessToken();
        if (orgMrn != null && !orgMrn.isEmpty()) {
            accessToken.setOtherClaims(AccessControlUtil.ORG_PROPERTY_NAME, orgMrn);
        }
        if (permissions != null && !permissions.isEmpty()) {
            accessToken.setOtherClaims(AccessControlUtil.PERMISSIONS_PROPERTY_NAME, permissions);
        }
        String bearerTokenString = UUID.randomUUID().toString();

        RefreshableKeycloakSecurityContext ksc = new RefreshableKeycloakSecurityContext(null, null, bearerTokenString, accessToken, null, null, null);
        Set<String> rolesSet = new HashSet<>();
        String[] roleArr = roles.split(",");
        for(String role : roleArr) {
            rolesSet.add(role.trim());
        }
        KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal = new KeycloakPrincipal<>("name", ksc);
        SimpleKeycloakAccount account = new SimpleKeycloakAccount(principal, rolesSet, ksc);
        Collection<GrantedAuthority> authorities = generateGrantedAuthority(roles);
        return new KeycloakAuthenticationToken(account, false, authorities);
    }

    /**
     * Helper function of build fake PreAuthenticatedAuthenticationToken - used for x509 authentication
     * @param orgMrn
     * @param roles
     * @param permissions
     * @return
     */
    public static PreAuthenticatedAuthenticationToken generatePreAuthenticatedAuthenticationToken(String orgMrn, String roles, String permissions) {
        Collection<GrantedAuthority> authorities = generateGrantedAuthority(roles);
        InetOrgPerson.Essence essence = new InetOrgPerson.Essence();
        String username = "urn:mrn:mcl:user:dma:dmauser";
        essence.setUsername(username);
        essence.setUid(username);
        essence.setDn("O="+orgMrn);
        essence.setO(orgMrn);
        essence.setCn(new String[] {"dmauser"});
        essence.setAuthorities(authorities);

        PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(essence.createUserDetails(), null, authorities);
        return token;
    }

    public static Collection<GrantedAuthority> generateGrantedAuthority(String roles) {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        String[] roleArr = roles.split(",");
        for(String role : roleArr) {
            authorities.add(new SimpleGrantedAuthority(role.trim()));
        }
        return authorities;
    }
}
