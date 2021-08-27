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
package net.maritimeconnectivity.identityregistry.utils;

import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.identityregistry.model.database.Agent;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.model.database.entities.User;
import net.maritimeconnectivity.identityregistry.services.AgentService;
import net.maritimeconnectivity.identityregistry.services.EntityService;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;


@Component("accessControlUtil")
@Slf4j
public class AccessControlUtil {

    public static final String ORG_PROPERTY_NAME = "org";
    public static final String MRN_PROPERTY_NAME = "mrn";
    public static final String PERMISSIONS_PROPERTY_NAME = "permissions";
    public static final String UNKNOWN_AUTHENTICATION_METHOD = "Unknown authentication method: {}";

    @Autowired
    private HasRoleUtil hasRoleUtil;

    @Autowired
    private OrganizationService organizationService;

    @Autowired
    private AgentService agentService;

    @Autowired
    private EntityService<User> userService;

    public boolean hasAccessToOrg(String orgMrn) {
        if (orgMrn == null || orgMrn.trim().isEmpty()) {
            log.debug("The orgMrn was empty!");
            return false;
        }
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        // First check if the user is a SITE_ADMIN, in which case he gets access.
        for (GrantedAuthority authority : auth.getAuthorities()) {
            String role = authority.getAuthority();
            log.debug("User has role: {}", role);
            if ("ROLE_SITE_ADMIN".equals(role)) {
                return true;
            }
        }
        log.debug("User not a SITE_ADMIN");
        // Check if the user is part of the organization
        if (auth instanceof KeycloakAuthenticationToken) {
            log.debug("OIDC authentication in process");
            // Keycloak authentication
            KeycloakAuthenticationToken kat = (KeycloakAuthenticationToken) auth;
            KeycloakSecurityContext ksc = (KeycloakSecurityContext) kat.getCredentials();
            Map<String, Object> otherClaims = ksc.getToken().getOtherClaims();
            if (otherClaims.containsKey(AccessControlUtil.MRN_PROPERTY_NAME)) {
                String mrn = (String) otherClaims.get(AccessControlUtil.MRN_PROPERTY_NAME);
                String org = "";
                if (mrn != null) {
                    String[] mrnParts = mrn.split(":");
                    if (mrnParts.length < 7)
                        return false;
                    org = String.format("urn:mrn:mcp:org:%s:%s", mrnParts[4], mrnParts[5]);
                }
                if (org.equalsIgnoreCase(orgMrn)) {
                    log.debug("Entity from org: {} is in {}", org, orgMrn);
                    return true;
                }
                Organization organization = organizationService.getOrganizationByMrnNoFilter(orgMrn);
                Organization agentOrganization = organizationService.getOrganizationByMrnNoFilter(org);
                if (organization != null && agentOrganization != null) {
                    List<Agent> agents = agentService.getAgentsByIdOnBehalfOfOrgAndIdActingOrg(organization.getId(), agentOrganization.getId());
                    if (!agents.isEmpty()) {
                        log.debug("Entity from org: {} is an agent for {}", org, orgMrn);
                        return true;
                    }
                }
            }
            log.debug("Entity from org: " + otherClaims.get(AccessControlUtil.ORG_PROPERTY_NAME) + " is not in " + orgMrn);
        } else if (auth instanceof PreAuthenticatedAuthenticationToken) {
            log.debug("Certificate authentication in process");
            // Certificate authentication
            PreAuthenticatedAuthenticationToken token = (PreAuthenticatedAuthenticationToken) auth;
            // Check that the Organization name of the accessed organization and the organization in the certificate is equal
            InetOrgPerson person = ((InetOrgPerson) token.getPrincipal());
            // The O(rganization) value in the certificate is an MRN
            String certOrgMrn = person.getO();
            if (orgMrn.equalsIgnoreCase(certOrgMrn)) {
                log.debug("Entity with O={} is in {}", certOrgMrn, orgMrn);
                return true;
            }
            Organization organization = organizationService.getOrganizationByMrnNoFilter(orgMrn);
            Organization agentOrganization = organizationService.getOrganizationByMrnNoFilter(certOrgMrn);
            if (organization != null && agentOrganization != null) {
                List<Agent> agents = agentService.getAgentsByIdOnBehalfOfOrgAndIdActingOrg(organization.getId(), agentOrganization.getId());
                if (!agents.isEmpty()) {
                    log.debug("Entity with O={} is an agent for {}", certOrgMrn, orgMrn);
                    return true;
                }
            }
            log.debug("Entity with O={} is not in {}", certOrgMrn, orgMrn);
        } else {
            log.debug(UNKNOWN_AUTHENTICATION_METHOD, auth.getClass().getName());
        }
        return false;
    }

    public static boolean isUserSync(String userSyncMRN, String userSyncO, String userSyncOU, String userSyncC) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof PreAuthenticatedAuthenticationToken) {
            log.debug("Certificate authentication of user sync'er in process");
            // Certificate authentication
            PreAuthenticatedAuthenticationToken token = (PreAuthenticatedAuthenticationToken) auth;
            // Check that the Organization name of the accessed organization and the organization in the certificate is equal
            InetOrgPerson person = ((InetOrgPerson) token.getPrincipal());
            if (userSyncMRN.equalsIgnoreCase(person.getUid()) && userSyncO.equalsIgnoreCase(person.getO())
                    // Hack alert! There is no country property in this type, so we misuse PostalAddress...
                    && userSyncOU.equals(person.getOu()) && userSyncC.equals(person.getPostalAddress())) {
                log.debug("User sync'er accepted!");
                return true;
            }
            log.debug("This was not the user-syncer! {}~{}, {}~{}, {}~{}, {}~{}", userSyncMRN, person.getUid(),
                    userSyncO, person.getO(), userSyncOU, person.getOu(), userSyncC, person.getPostalAddress());
        }
        return false;
    }

    public boolean isUser(String userMRN) {
        User user = this.userService.getByMrn(userMRN);
        Organization organization = this.organizationService.getOrganizationById(user.getIdOrganization());
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof KeycloakAuthenticationToken) {
            KeycloakAuthenticationToken kat = (KeycloakAuthenticationToken) auth;
            KeycloakSecurityContext ksc = (KeycloakSecurityContext) kat.getCredentials();
            Map<String, Object> otherClaims = ksc.getToken().getOtherClaims();
            String mrn = (String) otherClaims.get(MRN_PROPERTY_NAME);
            if (mrn != null) {
                String[] mrnParts = mrn.split(":");
                if (mrnParts.length < 7)
                    return false;
                String org = String.format("urn:mrn:mcp:org:%s:%s", mrnParts[4], mrnParts[5]);
                return user.getMrn().equals(mrn) && organization.getMrn().equals(org);
            }
        } else if (auth instanceof PreAuthenticatedAuthenticationToken) {
            PreAuthenticatedAuthenticationToken token = (PreAuthenticatedAuthenticationToken) auth;
            InetOrgPerson person = ((InetOrgPerson) token.getPrincipal());
            String mrn = person.getUid();
            String org = person.getO();
            if (mrn != null && org != null) {
                return user.getMrn().equals(mrn) && organization.getMrn().equals(org);
            }
        }
        if (auth != null) {
            log.debug(UNKNOWN_AUTHENTICATION_METHOD, auth.getClass().getName());
        }
        return false;
    }

    public static boolean hasPermission(String permission) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof KeycloakAuthenticationToken) {
            log.debug("OIDC permission lookup");
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
            log.debug("Certificate permission lookup");
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
                log.debug(UNKNOWN_AUTHENTICATION_METHOD, auth.getClass().getName());
            }
        }
        return false;
    }

    public static List<String> getMyRoles() {
        log.debug("Role lookup");
        List<String> roles = new ArrayList<>();
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            for (GrantedAuthority authority : auth.getAuthorities()) {
                roles.add(authority.getAuthority());
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
            log.debug("User has role {}", role);
            return true;
        } catch (Exception ade) {
            log.debug("user does not have role {}", role);
            return false;
        }
    }
}
