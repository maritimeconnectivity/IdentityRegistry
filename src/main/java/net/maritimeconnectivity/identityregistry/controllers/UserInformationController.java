/*
 * Copyright 2018 Danish Maritime Authority
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.maritimeconnectivity.identityregistry.controllers;

import net.maritimeconnectivity.identityregistry.exception.McpBasicRestException;
import net.maritimeconnectivity.identityregistry.model.database.Agent;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.model.database.entities.User;
import net.maritimeconnectivity.identityregistry.services.AgentService;
import net.maritimeconnectivity.identityregistry.services.EntityService;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import net.maritimeconnectivity.identityregistry.services.RoleService;
import net.maritimeconnectivity.identityregistry.utils.AccessControlUtil;
import net.maritimeconnectivity.identityregistry.utils.MCPIdRegConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping(value = "service")
public class UserInformationController {

    // Data that identifies the User sync'er
    @Value("${net.maritimeconnectivity.idreg.user-sync.c}")
    private String userSyncC;
    @Value("${net.maritimeconnectivity.idreg.user-sync.o}")
    private String userSyncO;
    @Value("${net.maritimeconnectivity.idreg.user-sync.ou}")
    private String userSyncOU;
    @Value("${net.maritimeconnectivity.idreg.user-sync.mrn}")
    private String userSyncMRN;

    @Autowired
    private RoleService roleService;

    @Autowired
    private OrganizationService organizationService;

    private EntityService<User> userService;

    @Autowired
    private AgentService agentService;

    @Autowired
    public void setUserService(EntityService<User> userService) {
        this.userService = userService;
    }

    @RequestMapping(
            value = "/{userMrn}/roles",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8"
    )
    public ResponseEntity<List<String>> getUserRoles(HttpServletRequest request, @PathVariable String userMrn) throws McpBasicRestException {
        if (!AccessControlUtil.isUserSync(this.userSyncMRN, this.userSyncO, this.userSyncOU, this.userSyncC)) {
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        }

        User user = this.userService.getByMrn(userMrn);
        if (user != null && user.getPermissions() != null) {
            List<String> userPermissions = Arrays.asList(user.getPermissions().split(",")).parallelStream().map(String::trim).collect(Collectors.toList());

            List<String> userRoles = new ArrayList<>();
            userPermissions.forEach(permission -> roleService.getRolesByIdOrganizationAndPermission(user.getIdOrganization(), permission).forEach(role -> userRoles.add(role.getRoleName())));

            return new ResponseEntity<>(userRoles, HttpStatus.OK);
        }
        return new ResponseEntity<>(Collections.singletonList("ROLE_USER"), HttpStatus.OK);
    }

    @RequestMapping(
            value = "/{userMrn}/acting-on-behalf-of",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8"
    )
    public ResponseEntity<List<String>> getOrgsToActOnBehalfOf(HttpServletRequest request, @PathVariable String userMrn) throws McpBasicRestException {
        if (!AccessControlUtil.isUserSync(this.userSyncMRN, this.userSyncO, this.userSyncOU, this.userSyncC)) {
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        }

        User user = this.userService.getByMrn(userMrn);

        if (user != null) {

            Organization organization = this.organizationService.getOrganizationById(user.getIdOrganization());

            if (organization != null) {
                List<Agent> agents = this.agentService.getAgentsByIdActingOrg(organization.getId());

                if (agents != null) {
                    List<String> orgs = new ArrayList<>();
                    agents.forEach(agent -> {
                        Organization org = this.organizationService.getOrganizationById(agent.getIdOnBehalfOfOrganization());
                        if (org != null) {
                            orgs.add(org.getMrn());
                        }
                    });
                    return new ResponseEntity<>(orgs, HttpStatus.OK);
                }
            }
        }

        return new ResponseEntity<>(new ArrayList<>(), HttpStatus.OK);
    }
}
