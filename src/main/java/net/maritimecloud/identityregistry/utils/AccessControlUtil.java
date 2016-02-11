/* Copyright 2016 Danish Maritime Authority.
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
package net.maritimecloud.identityregistry.utils;

import java.util.Map;

import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.ldap.userdetails.InetOrgPerson;

public class AccessControlUtil {

    public static final String ORG_PROPERTY_NAME = "org";
    
    public static boolean hasAccessToOrg(String orgName, String orgShortName) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof KeycloakAuthenticationToken) {
            // Keycloak authentication
            KeycloakAuthenticationToken kat = (KeycloakAuthenticationToken) auth;
            KeycloakSecurityContext ksc = (KeycloakSecurityContext)kat.getCredentials();
            Map<String, Object> otherClaims = ksc.getToken().getOtherClaims();
            if (otherClaims.containsKey(AccessControlUtil.ORG_PROPERTY_NAME) &&
                    ((String)otherClaims.get(AccessControlUtil.ORG_PROPERTY_NAME)).toLowerCase().equals(orgShortName.toLowerCase())) {
                return true;
            }
        } else if (auth instanceof UsernamePasswordAuthenticationToken) {
            // username / ADMIN interface authentication
            UsernamePasswordAuthenticationToken upat = (UsernamePasswordAuthenticationToken) auth;
            if (upat.getName().equals(orgShortName)) {
                return true;
            }
        } else if (auth instanceof PreAuthenticatedAuthenticationToken) {
            // Certificate authentication
            PreAuthenticatedAuthenticationToken token = (PreAuthenticatedAuthenticationToken) auth;
            // Check that the Organization name of the accessed organization and the organization in the certificate is equal
            String certOrg = ((InetOrgPerson)token.getPrincipal()).getO();
            if (orgName.equals(certOrg)) {
                return true;
            }
        } else {
            System.out.println("Unknown authentication method: " + auth.getClass());
        }
        
        return false;
    }
}
