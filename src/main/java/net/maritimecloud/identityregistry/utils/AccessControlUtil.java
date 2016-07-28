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

import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.stereotype.Component;


@Component("accessControlUtil")
public class AccessControlUtil {

    @Autowired
    private HasRoleUtil hasRoleUtil;
    public static final String ORG_PROPERTY_NAME = "org";
    public static final String PERMISSIONS_PROPERTY_NAME = "permissions";

    private static final Logger logger = LoggerFactory.getLogger(AccessControlUtil.class);

    public static boolean hasAccessToOrg(String orgShortName) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        // First check if the user is a SITE_ADMIN, in which case he gets access.
        for (GrantedAuthority authority : auth.getAuthorities()) {
            String role = authority.getAuthority();
            if ("ROLE_SITE_ADMIN".equals(role)) {
                return true;
            }
        }
        // Check if the user is part of the organization
        if (auth instanceof KeycloakAuthenticationToken) {
            logger.debug("OIDC authentication in process");
            // Keycloak authentication
            KeycloakAuthenticationToken kat = (KeycloakAuthenticationToken) auth;
            KeycloakSecurityContext ksc = (KeycloakSecurityContext) kat.getCredentials();
            Map<String, Object> otherClaims = ksc.getToken().getOtherClaims();
            if (otherClaims.containsKey(AccessControlUtil.ORG_PROPERTY_NAME) &&
                    ((String) otherClaims.get(AccessControlUtil.ORG_PROPERTY_NAME)).toLowerCase().equals(orgShortName.toLowerCase())) {
                logger.debug("Entity from org: " + otherClaims.get(AccessControlUtil.ORG_PROPERTY_NAME) + " is in " + orgShortName);
                return true;
            }
            logger.debug("Entity from org: " + otherClaims.get(AccessControlUtil.ORG_PROPERTY_NAME) + " is not in " + orgShortName);
        } else if (auth instanceof PreAuthenticatedAuthenticationToken) {
            logger.debug("Certificate authentication in process");
            // Certificate authentication
            PreAuthenticatedAuthenticationToken token = (PreAuthenticatedAuthenticationToken) auth;
            // Check that the Organization name of the accessed organization and the organization in the certificate is equal
            InetOrgPerson person = ((InetOrgPerson) token.getPrincipal());
            // The O(rganization) value looks like this in the certificate: <org shortname>;<org fullname>
            String certOrg = person.getO();
            int idx = certOrg.indexOf(";");
            if (idx < 1) {
                return false;
            }
            certOrg = certOrg.substring(0, idx);
            if (orgShortName.equals(certOrg)) {
                logger.debug("Entity with O=" + certOrg + " is in " + orgShortName);
                return true;
            }
            logger.debug("Entity with O=" + certOrg + " is not in " + orgShortName);
        } else {
            if (auth != null) {
                logger.debug("Unknown authentication method: " + auth.getClass());
            }
        }
        return false;
    }

    public static boolean isUserSync(String userSyncCN, String userSyncO, String userSyncOU, String userSyncC) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof PreAuthenticatedAuthenticationToken) {
            logger.debug("Certificate authentication of user sync'er in process");
            // Certificate authentication
            PreAuthenticatedAuthenticationToken token = (PreAuthenticatedAuthenticationToken) auth;
            // Check that the Organization name of the accessed organization and the organization in the certificate is equal
            InetOrgPerson person = ((InetOrgPerson) token.getPrincipal());
            if (userSyncCN.equals(person.getCn()[0]) && userSyncO.equals(person.getO())
                    // Hack alert! There is no country property in this type, so we misuse PostalAddress...
                    && userSyncOU.equals(person.getOu()) && userSyncC.equals(person.getPostalAddress())) {
                logger.debug("User sync'er accepted!");
                return true;
            }
            logger.debug("This was not the user-sync'er! " + userSyncCN + "~" + person.getCn()[0] + ", " + userSyncO + "~"
                    + person.getO() + ", " + userSyncOU + "~" + person.getOu() + ", " + userSyncC + "~" + person.getPostalAddress());
        }
        return false;
    }

    public static boolean hasPermission(String permission) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof KeycloakAuthenticationToken) {
            logger.debug("OIDC permission lookup");
            // Keycloak authentication
            KeycloakAuthenticationToken kat = (KeycloakAuthenticationToken) auth;
            KeycloakSecurityContext ksc = (KeycloakSecurityContext) kat.getCredentials();
            Map<String, Object> otherClaims = ksc.getToken().getOtherClaims();
            if (otherClaims.containsKey(AccessControlUtil.PERMISSIONS_PROPERTY_NAME)) {
                String usersPermissions = (String) otherClaims.get(AccessControlUtil.PERMISSIONS_PROPERTY_NAME);
                String[] permissionList = usersPermissions.split(",");
                for (String per : permissionList) {
                    if (per.equalsIgnoreCase(permission)) {
                        return true;
                    }
                }
            }
        } else if (auth instanceof PreAuthenticatedAuthenticationToken) {
            logger.debug("Certificate permission lookup");
            // Certificate authentication
            PreAuthenticatedAuthenticationToken token = (PreAuthenticatedAuthenticationToken) auth;
            // Check that the permission is granted to this user
            InetOrgPerson person = ((InetOrgPerson) token.getPrincipal());
            Collection<GrantedAuthority> authorities = person.getAuthorities();
            for (GrantedAuthority authority : authorities) {
                String usersPermissions = authority.getAuthority();
                String[] permissionList = usersPermissions.split(",");
                for (String per : permissionList) {
                    if (per.equalsIgnoreCase(permission)) {
                        return true;
                    }
                }
            }
        } else {
            if (auth != null) {
                logger.debug("Unknown authentication method: " + auth.getClass());
            }
        }
        return false;
    }

    public static String getMyRoles() {
        logger.debug("Role lookup");
        String roles = "";
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            for (GrantedAuthority authority : auth.getAuthorities()) {
                String role = authority.getAuthority();
                if (!roles.isEmpty()) {
                    roles += ",";
                }
                roles += role;
            }
        }
        return roles;
    }

    public boolean hasAnyRoles(List<String> roles) {
        for (String lookingForRole : roles) {
            if (lookingForRole != null && this.hasRole(lookingForRole)) {
                return true;
            }
        }
        return false;
    }

    public boolean hasRole(String role) {
        try {
            // If the user does not have the role (or a role that is above it in the role hierarchy)
            // an exception will be thrown by Spring Security.
            hasRoleUtil.testRole(role);
            logger.debug("user has role " + role);
            return true;
        } catch (Exception ade) {
            logger.debug("user does not have role " + role);
            return false;
        }
    }
}
