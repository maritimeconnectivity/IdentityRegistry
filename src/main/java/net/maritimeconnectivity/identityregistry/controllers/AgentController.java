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

import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.identityregistry.exception.McpBasicRestException;
import net.maritimeconnectivity.identityregistry.model.database.Agent;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.services.AgentService;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import net.maritimeconnectivity.identityregistry.utils.MCPIdRegConstants;
import org.springdoc.api.annotations.ParameterObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.net.URI;
import java.net.URISyntaxException;

@RestController
@RequestMapping(value={"oidc", "x509"})
@Slf4j
public class AgentController {

    @Autowired
    private OrganizationService organizationService;

    @Autowired
    private AgentService agentService;

    /**
     * Returns all the agents for an organization
     *
     * @return A page of agents for an organization
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/agents",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @ResponseBody
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn)")
    public Page<Agent> getAgents(HttpServletRequest request, @PathVariable String orgMrn, @ParameterObject Pageable pageable) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            return this.agentService.getAgentsByIdOnBehalfOfOrg(org.getId(), pageable);
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns who the organization can act on behalf of
     *
     * @return A page of agents
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/acting-on-behalf-of",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @ResponseBody
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn)")
    public Page<Agent> getActingOnBehalfOf(HttpServletRequest request, @PathVariable String orgMrn, @ParameterObject Pageable pageable) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            return this.agentService.getAgentsByIdActingOrg(org.getId(), pageable);
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Get a specific agent
     *
     * @return an agent
     * @throws McpBasicRestException
     */
    @GetMapping(
            value = "/api/org/{orgMrn}/agent/{agentId}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @ResponseBody
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<Agent> getAgent(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable Long agentId) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            Agent agent = this.agentService.getById(agentId);
            if (agent == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.AGENT_NOT_FOUND, request.getServletPath());
            }
            if (agent.getIdOnBehalfOfOrganization().equals(org.getId()) || agent.getIdActingOrganization().equals(org.getId())) {
                return new ResponseEntity<>(agent, HttpStatus.OK);
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        }
        throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
    }

    /**
     * Creates a new agent
     *
     * @return the created agent
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/{orgMrn}/agent",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<Agent> createAgent(HttpServletRequest request, @PathVariable String orgMrn, @Valid @RequestBody Agent input) throws McpBasicRestException {
        Organization organization = this.organizationService.getOrganizationByMrn(orgMrn);
        Organization actingOrg = this.organizationService.getOrganizationById(input.getIdActingOrganization());
        if (organization != null && actingOrg != null) {
            input.setIdOnBehalfOfOrganization(organization.getId());
            Agent agent = null;
            HttpHeaders headers = new HttpHeaders();
            try {
                agent = this.agentService.save(input);
                String path = request.getRequestURL().append("/").append(agent.getId().toString()).toString();
                headers.setLocation(new URI(path));
            } catch (DataIntegrityViolationException e) {
                throw new McpBasicRestException(HttpStatus.CONFLICT, MCPIdRegConstants.ERROR_STORING_ENTITY, request.getServletPath());
            } catch (URISyntaxException e) {
                log.error("Could not create Location header", e);
            }
            return new ResponseEntity<>(agent, headers, HttpStatus.CREATED);
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Updates an existing agent
     *
     * @return the updated agent
     * @throws McpBasicRestException
     */
    @PutMapping(
            value = "/api/org/{orgMrn}/agent/{agentId}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<Agent> updateAgent(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable Long agentId, @Valid @RequestBody Agent input) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            Agent agent = this.agentService.getById(agentId);
            if (agent == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.AGENT_NOT_FOUND, request.getServletPath());
            }
            if (!input.getIdOnBehalfOfOrganization().equals(agent.getIdOnBehalfOfOrganization()) || !org.getId().equals(input.getIdOnBehalfOfOrganization())) {
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.URL_DATA_MISMATCH, request.getServletPath());
            }
            agent = input.copyTo(agent);
            this.agentService.save(agent);

            return new ResponseEntity<>(agent, HttpStatus.OK);
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Deletes an agent
     *
     * @return a reply
     * @throws McpBasicRestException
     */
    @DeleteMapping(
            value = "/api/org/{orgMrn}/agent/{agentId}"
    )
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> deleteAgent(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable Long agentId) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            Agent agent = this.agentService.getById(agentId);
            if (agent == null) {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.AGENT_NOT_FOUND, request.getServletPath());
            }
            if (org.getId().equals(agent.getIdOnBehalfOfOrganization())) {
                this.agentService.delete(agentId);
                return new ResponseEntity<>(HttpStatus.OK);
            }
            throw new McpBasicRestException(HttpStatus.FORBIDDEN, MCPIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }
}
