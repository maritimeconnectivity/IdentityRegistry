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


import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.model.database.Role;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import net.maritimeconnectivity.identityregistry.services.RoleService;
import net.maritimeconnectivity.identityregistry.utils.MCPIdRegConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Slf4j
@Component
public class MCPOidcAuthenticationProvider implements AuthenticationProvider {

    private GrantedAuthoritiesMapper grantedAuthoritiesMapper;

    private OrganizationService organizationService;
    private RoleService roleService;

    @Override
    public Authentication authenticate(Authentication authentication) {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        JwtAuthenticationToken token = (JwtAuthenticationToken) authentication;
        Jwt jwtToken = token.getToken();

        Organization org = null;
        String mrn = jwtToken.getClaimAsString(MCPIdRegConstants.MRN_PROPERTY_NAME);
        if (mrn != null) {
            String[] mrnParts = mrn.split(":");
            if (mrnParts.length >= 7) {
                String orgMrn = String.format("urn:mrn:mcp:org:%s:%s", mrnParts[4], mrnParts[5]);
                log.debug("Found org mrn: {}", orgMrn);
                org = organizationService.getOrganizationByMrnNoFilter(orgMrn);
            }
        }

        if (org != null) {
            List<String> usersPermissions = jwtToken.getClaimAsStringList(MCPIdRegConstants.PERMISSIONS_PROPERTY_NAME);
            if (usersPermissions != null) {
                for (String permission : usersPermissions) {
                    String[] auths = permission.split(",");
                    for (String auth : auths) {
                        log.debug("Looking up role: {}", auth);
                        List<Role> foundRoles = roleService.getRolesByIdOrganizationAndPermission(org.getId(), auth);
                        if (foundRoles != null) {
                            for (Role foundRole : foundRoles) {
                                log.debug("Replacing role {}, with: {}", auth, foundRole.getRoleName());
                                grantedAuthorities.add(new SimpleGrantedAuthority(foundRole.getRoleName()));
                            }
                        }
                    }
                }
                if (grantedAuthorities.isEmpty()) {
                    grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
                }
            }
        }
        return new JwtAuthenticationToken(jwtToken, mapTheAuthorities(grantedAuthorities));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private Collection<? extends GrantedAuthority> mapTheAuthorities(
            Collection<? extends GrantedAuthority> authorities) {
        return grantedAuthoritiesMapper != null
                ? grantedAuthoritiesMapper.mapAuthorities(authorities)
                : authorities;
    }

    @Autowired
    public void setGrantedAuthoritiesMapper(GrantedAuthoritiesMapper grantedAuthoritiesMapper) {
        this.grantedAuthoritiesMapper = grantedAuthoritiesMapper;
    }

    @Autowired
    public void setOrganizationService(OrganizationService organizationService) {
        this.organizationService = organizationService;
    }

    @Autowired
    public void setRoleService(RoleService roleService) {
        this.roleService = roleService;
    }
}
