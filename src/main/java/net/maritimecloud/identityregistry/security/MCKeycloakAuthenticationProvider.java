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
package net.maritimecloud.identityregistry.security;


import net.maritimecloud.identityregistry.model.database.Organization;
import net.maritimecloud.identityregistry.model.database.Role;
import net.maritimecloud.identityregistry.services.OrganizationService;
import net.maritimecloud.identityregistry.services.RoleService;
import net.maritimecloud.identityregistry.utils.AccessControlUtil;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.account.KeycloakRole;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

public class MCKeycloakAuthenticationProvider extends KeycloakAuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(MCKeycloakAuthenticationProvider.class);

    private GrantedAuthoritiesMapper grantedAuthoritiesMapper;

    @Autowired
    private OrganizationService organizationService;
    @Autowired
    private RoleService roleService;

    @Override
    public void setGrantedAuthoritiesMapper(GrantedAuthoritiesMapper grantedAuthoritiesMapper) {
        this.grantedAuthoritiesMapper = grantedAuthoritiesMapper;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<GrantedAuthority>();
        KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) authentication;
        KeycloakSecurityContext ksc = (KeycloakSecurityContext)token.getCredentials();
        Map<String, Object> otherClaims = ksc.getToken().getOtherClaims();

        Organization org = null;
        if (otherClaims.containsKey(AccessControlUtil.ORG_PROPERTY_NAME)) {
            String orgShortName = (String) otherClaims.get(AccessControlUtil.ORG_PROPERTY_NAME);
            logger.debug("Found org short name: " + orgShortName);
            org = organizationService.getOrganizationByShortName(orgShortName);

            if (org != null) {
                if (otherClaims.containsKey(AccessControlUtil.PERMISSIONS_PROPERTY_NAME)) {
                    String usersPermissions = (String) otherClaims.get(AccessControlUtil.PERMISSIONS_PROPERTY_NAME);
                    String[] permissionList = usersPermissions.split(",");
                    for (String permission : permissionList) {
                        String[] auths = permission.split(",");
                        for (String auth : auths) {
                            logger.debug("Looking up role: " + auth);
                            List<Role> foundRoles = roleService.getRolesByIdOrganizationAndPermission(org.getId(), auth);
                            if (foundRoles != null) {
                                for (Role foundRole : foundRoles) {
                                    logger.debug("Replacing role " + auth + ", with: " + foundRole.getRoleName());
                                    grantedAuthorities.add(new KeycloakRole(foundRole.getRoleName()));
                                }
                            }
                        }
                    }
                }
                if (grantedAuthorities.isEmpty()) {
                    grantedAuthorities.add(new KeycloakRole("ROLE_USER"));
                }
            }
        }
        return new KeycloakAuthenticationToken(token.getAccount(), mapAuthorities(grantedAuthorities));
    }

    private Collection<? extends GrantedAuthority> mapAuthorities(
            Collection<? extends GrantedAuthority> authorities) {
        return grantedAuthoritiesMapper != null
                ? grantedAuthoritiesMapper.mapAuthorities(authorities)
                : authorities;
    }

}
