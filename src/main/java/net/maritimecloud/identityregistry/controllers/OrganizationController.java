/* Copyright 2015 Danish Maritime Authority.
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

import org.springframework.web.bind.annotation.RestController;

import net.maritimecloud.identityregistry.model.Organization;
import net.maritimecloud.identityregistry.model.Ship;
import net.maritimecloud.identityregistry.services.OrganizationService;
import net.maritimecloud.identityregistry.services.ShipService;
import net.maritimecloud.identityregistry.utils.PasswordUtil;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;


@RestController
public class OrganizationController {
    private OrganizationService organizationService;
    private ShipService shipService;

    @Autowired
    public void setOrganizationService(OrganizationService organizationService) {
        this.organizationService = organizationService;
    }
	
    @Autowired
    public void setShipService(ShipService shipService) {
        this.shipService = shipService;
    }
    /**
     * Receives an application for a new organization and root-user 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/apply",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<?> applyOrganization(HttpServletRequest request, @RequestBody Organization input) {
        /*if (request.getSession() != null) {
        	return "{\"error\":\"No session\"}";
        }
        return "{\"status\":\"session found!\"}";*/
    	// Create password to be returned
    	String newPassword = PasswordUtil.generatePassword();
    	String hashedPassword = PasswordUtil.hashPassword(newPassword);
    	input.setPassword(newPassword);
    	input.setPasswordHash(hashedPassword);
    	Organization newOrg = this.organizationService.saveOrganization(input);
    	return new ResponseEntity<Organization>(newOrg, HttpStatus.OK);
    }

    /**
     * Returns info about the organization identified by the given ID 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgId}",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<?> getOrganization(HttpServletRequest request, @PathVariable Long orgId) {
        /*if (request.getSession() != null) {
        	return "{\"error\":\"No session\"}";
        }
        return "{\"status\":\"session found!\"}";*/
    	Organization org = this.organizationService.getOrganizationById(orgId);
    	return new ResponseEntity<Organization>(org, HttpStatus.OK);
    }
    
    /**
     * Updates info about the organization identified by the given ID 
     * @return a http reply
     */
    @RequestMapping(
            value = "/api/org/{orgId}",
            method = RequestMethod.PUT)
    @ResponseBody
    public ResponseEntity<?> updateOrganization(HttpServletRequest request, @PathVariable Long orgId, @RequestBody Organization input) {
        /*if (request.getSession() != null) {
        	return "{\"error\":\"No session\"}";
        }
        return "{\"status\":\"session found!\"}";*/
    	Organization org = this.organizationService.getOrganizationById(orgId);
    	if (org != null && org.getId() == orgId) {
    		input.copyTo(org);
    		this.organizationService.saveOrganization(org);
        	return new ResponseEntity<>(HttpStatus.OK);
    	}
    	return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    /**
     * Returns a list of ships owned by the organization identified by the given ID 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgId}/ships",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<?> getOrganizationShips(HttpServletRequest request, @PathVariable Long orgId) {
        /*if (request.getSession() != null) {
        	return "{\"error\":\"No session\"}";
        }
        return "{\"status\":\"session found!\"}";*/
    	List<Ship> ships = this.shipService.listOrgShips(orgId.intValue());
    	return new ResponseEntity<List<Ship> >(ships, HttpStatus.OK);
    }

    /**
     * Returns new password for the organization identified by the given ID 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgId}/getnewpassword",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<?> newOrgPassword(HttpServletRequest request, @PathVariable Long orgId) {
        /*if (request.getSession() != null) {
        	return "{\"error\":\"No session\"}";
        }
        return "{\"status\":\"session found!\"}";*/
    	String newPassword = PasswordUtil.generatePassword();
    	String hashedPassword = PasswordUtil.hashPassword(newPassword);
    	Organization org = this.organizationService.getOrganizationById(orgId);
    	org.setPasswordHash(hashedPassword);
    	this.organizationService.saveOrganization(org);
    	String jsonReturn = "{ \"password\":\"" + newPassword + "\"}";
    	return new ResponseEntity<String>(jsonReturn, HttpStatus.OK);
    }

    
    /* *
     * Returns and removes the last error
     * @return the last error
     
    @RequestMapping(
            value = "/error",
            method = RequestMethod.GET,
            produces = "text/plain;charset=UTF-8")
    @ResponseBody
    public String getError(HttpServletRequest request) {
        if (request.getSession() != null) {
            String error = (String)request.getSession().getAttribute("error");
            request.getSession().removeAttribute("error");
            return error;
        }
        return null;
    }*/
}
