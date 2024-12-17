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
package net.maritimeconnectivity.identityregistry.utils;

import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.identityregistry.model.database.Agent;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.model.database.entities.User;
import net.maritimeconnectivity.identityregistry.services.AgentService;
import net.maritimeconnectivity.identityregistry.services.EntityService;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

@Component("accessControlUtil")
@Slf4j
public class AccessControlUtil {

    private HasRoleUtil hasRoleUtil;

    private MrnUtil mrnUtil;

    private OrganizationService organizationService;

    private AgentService agentService;

    private EntityService<User> userService;

    private RoleHierarchy roleHierarchy;

    public boolean hasAccessToOrg(String orgMrn, String roleNeeded) {
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
        switch (auth) {
            case JwtAuthenticationToken kat -> {
                log.debug("OIDC authentication in process");
                // Keycloak authentication
                Map<String, Object> otherClaims = kat.getTokenAttributes();
                if (otherClaims.containsKey(MCPIdRegConstants.MRN_PROPERTY_NAME)) {
                    String mrn = (String) otherClaims.get(MCPIdRegConstants.MRN_PROPERTY_NAME);
                    String org = (String) otherClaims.get(MCPIdRegConstants.ORG_PROPERTY_NAME);
                    if (org == null || org.trim().isEmpty()) {
                        return false;
                    }
                    if (mrn != null) {
                        String[] mrnParts = mrn.split(":");
                        if (mrnParts.length < 7) {
                            return false;
                        }
                        if (!mrnUtil.getOrgShortNameFromEntityMrn(mrn).equals(mrnUtil.getOrgShortNameFromOrgMrn(org))) {
                            return false;
                        }
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
                            if (roleNeeded != null) {
                                if (!roleNeeded.startsWith(MCPIdRegConstants.ROLE_PREFIX))
                                    roleNeeded = MCPIdRegConstants.ROLE_PREFIX + roleNeeded;
                                for (Agent agent : agents) {
                                    List<SimpleGrantedAuthority> allowedGrantedAuthorities = agent.getAllowedRoles().stream()
                                            .map(allowedAgentRole -> new SimpleGrantedAuthority(allowedAgentRole.getRoleName()))
                                            .toList();
                                    Set<GrantedAuthority> reachableGrantedAuthorities =
                                            new HashSet<>(roleHierarchy.getReachableGrantedAuthorities(allowedGrantedAuthorities));
                                    final String finalRoleNeeded = roleNeeded;
                                    if (reachableGrantedAuthorities.stream().anyMatch(ga -> finalRoleNeeded.equals(ga.getAuthority())))
                                        return true;
                                }
                                log.debug("Entity from org: {} who is agent for {} does not have the needed role {}", org, orgMrn, roleNeeded);
                                return false;
                            }
                            return true;
                        }
                    }
                }
                log.debug("Entity from org: {} is not in {}", otherClaims.get(MCPIdRegConstants.ORG_PROPERTY_NAME), orgMrn);
            }
            case PreAuthenticatedAuthenticationToken token -> {
                log.debug("Certificate authentication in process");
                // Certificate authentication
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
                        if (roleNeeded != null) {
                            if (!roleNeeded.startsWith(MCPIdRegConstants.ROLE_PREFIX))
                                roleNeeded = MCPIdRegConstants.ROLE_PREFIX + roleNeeded;
                            for (Agent agent : agents) {
                                List<SimpleGrantedAuthority> allowedGrantedAuthorities = agent.getAllowedRoles().stream()
                                        .map(allowedAgentRole -> new SimpleGrantedAuthority(allowedAgentRole.getRoleName()))
                                        .toList();
                                Set<GrantedAuthority> reachableGrantedAuthorities =
                                        new HashSet<>(roleHierarchy.getReachableGrantedAuthorities(allowedGrantedAuthorities));
                                if (reachableGrantedAuthorities.contains(new SimpleGrantedAuthority(roleNeeded)))
                                    return true;
                            }
                            log.debug("Entity with O={} who is agent for {} does does not have the needed role {}", certOrgMrn, orgMrn, roleNeeded);
                            return false;
                        }
                        return true;
                    }
                }
                log.debug("Entity with O={} is not in {}", certOrgMrn, orgMrn);
            }
            default -> log.debug(MCPIdRegConstants.UNKNOWN_AUTHENTICATION_METHOD, auth.getClass().getName());
        }
        return false;
    }

    public static boolean isUserSync(String userSyncMRN, String userSyncO, String userSyncOU, String userSyncC) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof PreAuthenticatedAuthenticationToken token) {
            log.debug("Certificate authentication of user sync'er in process");
            // Certificate authentication
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
        Organization organization = this.organizationService.getOrganizationByIdNoFilter(user.getIdOrganization());
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof JwtAuthenticationToken kat) {
            Map<String, Object> otherClaims = kat.getTokenAttributes();
            String mrn = (String) otherClaims.get(MCPIdRegConstants.MRN_PROPERTY_NAME);
            if (mrn != null) {
                String[] mrnParts = mrn.split(":");
                if (mrnParts.length < 7)
                    return false;
                String org = (String) otherClaims.get(MCPIdRegConstants.ORG_PROPERTY_NAME);
                return user.getMrn().equals(mrn) && organization.getMrn().equals(org);
            }
        } else if (auth instanceof PreAuthenticatedAuthenticationToken token) {
            InetOrgPerson person = ((InetOrgPerson) token.getPrincipal());
            String mrn = person.getUid();
            String org = person.getO();
            if (mrn != null && org != null) {
                return user.getMrn().equals(mrn) && organization.getMrn().equals(org);
            }
        }
        if (auth != null) {
            log.debug(MCPIdRegConstants.UNKNOWN_AUTHENTICATION_METHOD, auth.getClass().getName());
        }
        return false;
    }

    public List<String> getMyRoles(String orgMrn) {
        log.debug("Role lookup");
        List<String> roles = new ArrayList<>();
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Set<GrantedAuthority> userGrantedAuthorities;
        if (auth != null) {
            userGrantedAuthorities = new HashSet<>(roleHierarchy
                    .getReachableGrantedAuthorities(auth.getAuthorities()));
            for (GrantedAuthority authority : userGrantedAuthorities) {
                roles.add(authority.getAuthority());
            }
        } else {
            return roles;
        }
        // From here on we try to decide if the user is acting on behalf of another organization,
        // and if so we compute the reachable roles that they have there.
        String userOrgMrn = null;
        if (auth instanceof JwtAuthenticationToken jwtAuthenticationToken) {
            Map<String, Object> otherClaims = jwtAuthenticationToken.getTokenAttributes();
            String userMrn = (String) otherClaims.get(MCPIdRegConstants.MRN_PROPERTY_NAME);
            if (userMrn == null || userMrn.trim().isEmpty())
                return Collections.emptyList();
            String[] mrnParts = userMrn.split(":");
            if (mrnParts.length < 7)
                return Collections.emptyList();
            userOrgMrn = (String) otherClaims.get(MCPIdRegConstants.ORG_PROPERTY_NAME);
        } else if (auth instanceof PreAuthenticatedAuthenticationToken token) {
            InetOrgPerson person = ((InetOrgPerson) token.getPrincipal());
            userOrgMrn = person.getO();
        }
        if (!Objects.equals(orgMrn, userOrgMrn)) {
            Organization organization = organizationService.getOrganizationByMrn(orgMrn);
            Organization agentOrganization = organizationService.getOrganizationByMrn(userOrgMrn);
            if (organization == null || agentOrganization == null)
                return Collections.emptyList();
            List<Agent> agents = agentService.getAgentsByIdOnBehalfOfOrgAndIdActingOrg(organization.getId(), agentOrganization.getId());
            if (agents.isEmpty())
                return Collections.emptyList();
            Set<String> roleSet = new HashSet<>();
            for (Agent agent : agents) {
                Set<GrantedAuthority> agentGrantedAuthorities = new HashSet<>(roleHierarchy.getReachableGrantedAuthorities(agent.getAllowedRoles()
                        .stream().map(ar -> new SimpleGrantedAuthority(ar.getRoleName())).toList()));
                agentGrantedAuthorities.retainAll(userGrantedAuthorities);
                agentGrantedAuthorities.forEach(ga -> roleSet.add(ga.getAuthority()));
            }
            roles = new ArrayList<>(roleSet);
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

    @Autowired
    public void setHasRoleUtil(HasRoleUtil hasRoleUtil) {
        this.hasRoleUtil = hasRoleUtil;
    }

    @Autowired
    public void setMrnUtil(MrnUtil mrnUtil) {
        this.mrnUtil = mrnUtil;
    }

    @Lazy
    @Autowired
    public void setOrganizationService(OrganizationService organizationService) {
        this.organizationService = organizationService;
    }

    @Lazy
    @Autowired
    public void setAgentService(AgentService agentService) {
        this.agentService = agentService;
    }

    @Lazy
    @Autowired
    public void setUserService(EntityService<User> userService) {
        this.userService = userService;
    }

    @Autowired
    public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
        this.roleHierarchy = roleHierarchy;
    }
}
