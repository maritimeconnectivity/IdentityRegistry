/*
 * Copyright 2022 Maritime Connectivity Platform Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.maritimeconnectivity.identityregistry.security;

import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.model.database.Role;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import net.maritimeconnectivity.identityregistry.services.RoleService;
import net.maritimeconnectivity.identityregistry.utils.MCPIdRegConstants;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Component
@Slf4j
public class McpJwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final OrganizationService organizationService;
    private final RoleService roleService;

    private final GrantedAuthoritiesMapper grantedAuthoritiesMapper;

    public McpJwtGrantedAuthoritiesConverter(OrganizationService organizationService, RoleService roleService, GrantedAuthoritiesMapper grantedAuthoritiesMapper) {
        this.organizationService = organizationService;
        this.roleService = roleService;
        this.grantedAuthoritiesMapper = grantedAuthoritiesMapper;
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();

        Organization org = null;
        String mrn = jwt.getClaimAsString(MCPIdRegConstants.MRN_PROPERTY_NAME);
        if (mrn != null) {
            String[] mrnParts = mrn.split(":");
            if (mrnParts.length >= 7) {
                String orgMrn = String.format("urn:mrn:mcp:org:%s:%s", mrnParts[4], mrnParts[5]);
                log.debug("Found org mrn: {}", orgMrn);
                org = organizationService.getOrganizationByMrnNoFilter(orgMrn);
            }
        }

        if (org != null) {
            List<String> usersPermissions = jwt.getClaimAsStringList(MCPIdRegConstants.PERMISSIONS_PROPERTY_NAME);
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
        return new ArrayList<>(grantedAuthoritiesMapper.mapAuthorities(grantedAuthorities));
    }
}
