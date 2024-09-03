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
package net.maritimeconnectivity.identityregistry.controllers;

import io.swagger.v3.oas.annotations.Operation;
import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.identityregistry.exception.McpBasicRestException;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.model.database.Role;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import net.maritimeconnectivity.identityregistry.services.RoleService;
import net.maritimeconnectivity.identityregistry.utils.AccessControlUtil;
import net.maritimeconnectivity.identityregistry.utils.MCPIdRegConstants;
import net.maritimeconnectivity.identityregistry.utils.ValidateUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;

@Slf4j
@RestController
@RequestMapping(value = {"oidc", "x509"})
public class RoleController {

    private RoleService roleService;
    private OrganizationService organizationService;
    private AccessControlUtil accessControlUtil;

    /**
     * Returns a list of rolemappings for this organization
     *
     * @return a reply...
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/roles",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get the list of role mappings for the specified organization"
    )
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn, null)")
    public ResponseEntity<List<Role>> getRoles(HttpServletRequest request, @PathVariable String orgMrn) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            List<Role> roles = this.roleService.listFromOrg(org.getId());
            return new ResponseEntity<>(roles, HttpStatus.OK);
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    @PostMapping(
            value = "/api/org/{orgMrn}/role",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Create a new role mapping"
    )
    @PreAuthorize("(hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'ORG_ADMIN') and #input.roleName != 'ROLE_SITE_ADMIN') or hasRole('SITE_ADMIN')")
    public ResponseEntity<Role> createRole(HttpServletRequest request, @PathVariable String orgMrn, @Valid @RequestBody Role input, BindingResult bindingResult) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            if ((input.getRoleName().equals("ROLE_SITE_ADMIN") || input.getRoleName().equals("ROLE_APPROVE_ORG"))
                    && !accessControlUtil.hasRole("ROLE_SITE_ADMIN")) {
                throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            input.setIdOrganization(org.getId());
            Role newRole = null;
            HttpHeaders headers = new HttpHeaders();
            try {
                newRole = this.roleService.save(input);
                String path = request.getRequestURL().append("/").append(newRole.getId().toString()).toString();
                headers.setLocation(new URI(path));
            } catch (DataIntegrityViolationException e) {
                throw new McpBasicRestException(HttpStatus.CONFLICT, MCPIdRegConstants.ERROR_STORING_ENTITY, request.getServletPath());
            } catch (URISyntaxException e) {
                log.error("Could not create Location header", e);
            }
            return new ResponseEntity<>(newRole, headers, HttpStatus.CREATED);
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns info about the role identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/role/{roleId}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get a specific role mapping"
    )
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn, null)")
    public ResponseEntity<Role> getRole(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable Long roleId) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            Role role = this.roleService.getById(roleId);
            if (role == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ROLE_NOT_FOUND, request.getServletPath());
            }
            if (role.getIdOrganization().compareTo(org.getId()) == 0) {
                return new ResponseEntity<>(role, HttpStatus.OK);
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }

    }

    /**
     * Updates a Role
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @PutMapping(
            value = "/api/org/{orgMrn}/role/{roleId}"
    )
    @Operation(
            description = "Update a specific role mapping"
    )
    @PreAuthorize("(hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'ORG_ADMIN') and #input.roleName != 'ROLE_SITE_ADMIN') or hasRole('SITE_ADMIN')")
    public ResponseEntity<?> updateRole(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable Long roleId, @Valid @RequestBody Role input, BindingResult bindingResult) throws McpBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            Role role = this.roleService.getById(roleId);
            if (role == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ROLE_NOT_FOUND, request.getServletPath());
            }
            if (role.getIdOrganization().compareTo(org.getId()) != 0) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
            }
            if ((input.getRoleName().equals("ROLE_SITE_ADMIN") || input.getRoleName().equals("ROLE_APPROVE_ORG"))
                    && !accessControlUtil.hasRole("ROLE_SITE_ADMIN")) {
                throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
            }
            input.copyTo(role);
            this.roleService.save(role);
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Deletes a Role
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @DeleteMapping(
            value = "/api/org/{orgMrn}/role/{roleId}"
    )
    @Operation(
            description = "Delete a specific role mapping"
    )
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'ORG_ADMIN')")
    public ResponseEntity<?> deleteRole(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable Long roleId) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            Role role = this.roleService.getById(roleId);
            if (role == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ROLE_NOT_FOUND, request.getServletPath());
            }
            if (role.getIdOrganization().compareTo(org.getId()) == 0) {
                this.roleService.delete(roleId);
                return new ResponseEntity<>(HttpStatus.OK);
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns the list of roles of the current user in the given organization
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/role/myroles",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get the list of roles of the requesting user"
    )
    public ResponseEntity<List<String>> getMyRole(@PathVariable String orgMrn) {
        List<String> roles = accessControlUtil.getMyRoles(orgMrn);
        return new ResponseEntity<>(roles, HttpStatus.OK);
    }

    /**
     * Returns a list of available roles
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/role/available-roles",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
            description = "Get the list of available roles"
    )
    public ResponseEntity<List<String>> getAvailableRoles(@PathVariable String orgMrn) {
        // See net.maritimeconnectivity.identityregistry.security.MultiSecurityConfig for the role hierarchy
        List<String> roles = Arrays.asList("ROLE_SITE_ADMIN", "ROLE_ORG_ADMIN", "ROLE_ENTITY_ADMIN", "ROLE_USER_ADMIN",
                "ROLE_VESSEL_ADMIN", "ROLE_SERVICE_ADMIN", "ROLE_DEVICE_ADMIN", "ROLE_MMS_ADMIN",
                "ROLE_APPROVE_ORG", "ROLE_USER");
        return new ResponseEntity<>(roles, HttpStatus.OK);
    }

    @Autowired
    public void setRoleService(RoleService roleService) {
        this.roleService = roleService;
    }

    @Autowired
    public void setOrganizationService(OrganizationService organizationService) {
        this.organizationService = organizationService;
    }

    @Autowired
    public void setAccessControlUtil(AccessControlUtil accessControlUtil) {
        this.accessControlUtil = accessControlUtil;
    }
}
