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
package net.maritimecloud.identityregistry.controllers;

import net.maritimecloud.identityregistry.exception.McBasicRestException;
import net.maritimecloud.identityregistry.model.database.Organization;
import net.maritimecloud.identityregistry.model.database.Role;
import net.maritimecloud.identityregistry.services.OrganizationService;
import net.maritimecloud.identityregistry.services.RoleService;
import net.maritimecloud.identityregistry.utils.AccessControlUtil;
import net.maritimecloud.identityregistry.utils.MCIdRegConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@RestController
@RequestMapping(value={"oidc", "x509"})
public class RoleController {

    private RoleService roleService;
    private OrganizationService organizationService;

    @Autowired
    public void setCertificateService(RoleService roleService) {
        this.roleService = roleService;
    }
    @Autowired
    public void setOrganizationService(OrganizationService organizationService) {
        this.organizationService = organizationService;
    }
    /**
     * Returns a list of rolemappings for this organization
     *
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/roles",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<List<Role>> getCRL(HttpServletRequest request, @PathVariable String orgShortName) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            List<Role> roles = this.roleService.listOrgRoles(org.getId());
            return new ResponseEntity<List<Role>>(roles, HttpStatus.OK);
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    @RequestMapping(
            value = "/api/org/{orgShortName}/role",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<Role> createRole(HttpServletRequest request, @PathVariable String orgShortName, @RequestBody Role input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            input.setIdOrganization(org.getId());
            Role newRole = this.roleService.saveRole(input);
            return new ResponseEntity<Role>(newRole, HttpStatus.OK);
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns info about the role identified by the given ID
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/role/{roleId}",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<Role> getRole(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long roleId) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            Role role = this.roleService.getRoleById(roleId);
            if (role == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.USER_NOT_FOUND, request.getServletPath());
            }
            if (role.getIdOrganization().compareTo(org.getId()) == 0) {
                return new ResponseEntity<Role>(role, HttpStatus.OK);
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }

    }

    /**
     * Updates a Role
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/role/{roleId}",
            method = RequestMethod.PUT)
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<?> updateRole(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long roleId, @RequestBody Role input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            Role role = this.roleService.getRoleById(roleId);
            if (role == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.USER_NOT_FOUND, request.getServletPath());
            }
            if (role.getIdOrganization().compareTo(org.getId()) != 0) {
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
            }
            input.copyTo(role);
            this.roleService.saveRole(role);
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Deletes a Role
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/role/{roleId}",
            method = RequestMethod.DELETE)
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<?> deleteRole(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long roleId) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            Role role = this.roleService.getRoleById(roleId);
            if (role == null) {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.USER_NOT_FOUND, request.getServletPath());
            }
            if (role.getIdOrganization().compareTo(org.getId()) == 0) {
                this.roleService.deleteRole(roleId);
                return new ResponseEntity<>(HttpStatus.OK);
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns the roles of the current user
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/role/myroles",
            method = RequestMethod.GET,
            produces = "text/plain;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<String> getMyRole(HttpServletRequest request, @PathVariable String orgShortName) throws McBasicRestException {
        String roles = AccessControlUtil.getMyRoles();
        return new ResponseEntity<>(roles, HttpStatus.OK);
    }
}
