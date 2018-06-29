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

package net.maritimecloud.identityregistry.controllers;

import net.maritimecloud.identityregistry.exception.McBasicRestException;
import net.maritimecloud.identityregistry.model.database.Agent;
import net.maritimecloud.identityregistry.model.database.Organization;
import net.maritimecloud.identityregistry.model.database.entities.User;
import net.maritimecloud.identityregistry.services.AgentService;
import net.maritimecloud.identityregistry.services.EntityService;
import net.maritimecloud.identityregistry.services.OrganizationService;
import net.maritimecloud.identityregistry.services.RoleService;
import net.maritimecloud.identityregistry.utils.AccessControlUtil;
import net.maritimecloud.identityregistry.utils.MCIdRegConstants;
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
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping(value = "service")
public class UserInformationController {

    // Data that identifies the User sync'er
    @Value("${net.maritimecloud.idreg.user-sync.c}")
    private String userSyncC;
    @Value("${net.maritimecloud.idreg.user-sync.o}")
    private String userSyncO;
    @Value("${net.maritimecloud.idreg.user-sync.ou}")
    private String userSyncOU;
    @Value("${net.maritimecloud.idreg.user-sync.mrn}")
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
    public ResponseEntity<List<String>> getUserRoles(HttpServletRequest request, @PathVariable String userMrn) throws McBasicRestException {
        if (!AccessControlUtil.isUserSync(this.userSyncMRN, this.userSyncO, this.userSyncOU, this.userSyncC)) {
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        }

        User user = this.userService.getByMrn(userMrn);
        List<String> userPermissions = Arrays.asList(user.getPermissions().split(",")).parallelStream().map(String::trim).collect(Collectors.toList());

        List<String> userRoles = new ArrayList<>();
        userPermissions.forEach(permission -> roleService.getRolesByIdOrganizationAndPermission(user.getIdOrganization(), permission).forEach(role -> userRoles.add(role.getRoleName())));

        return new ResponseEntity<>(userRoles, HttpStatus.OK);
    }

    @RequestMapping(
            value = "/{userMrn}/orgs",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8"
    )
    public ResponseEntity<List<String>> getOrgsToActOnBehalfOf(HttpServletRequest request, @PathVariable String userMrn) throws McBasicRestException {
        if (!AccessControlUtil.isUserSync(this.userSyncMRN, this.userSyncO, this.userSyncOU, this.userSyncC)) {
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        }

        User user = this.userService.getByMrn(userMrn);

        Organization organization = this.organizationService.getOrganizationById(user.getIdOrganization());

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

        return new ResponseEntity<>(new ArrayList<>(), HttpStatus.OK);
    }
}
