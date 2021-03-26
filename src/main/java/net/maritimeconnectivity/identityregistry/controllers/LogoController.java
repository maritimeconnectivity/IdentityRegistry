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
package net.maritimeconnectivity.identityregistry.controllers;

import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.identityregistry.exception.McpBasicRestException;
import net.maritimeconnectivity.identityregistry.model.database.Logo;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import net.maritimeconnectivity.identityregistry.utils.ImageUtil;
import net.maritimeconnectivity.identityregistry.utils.MCPIdRegConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

@RestController
@RequestMapping(value={"oidc", "x509"})
@Slf4j
public class LogoController {

    private OrganizationService organizationService;

    @Autowired
    public void setOrganizationService(OrganizationService organizationService) {
        this.organizationService = organizationService;
    }

    /**
     * Creates a logo for an organization
     * @param request request to get servletPath
     * @param orgMrn resource location for organization
     * @param logo the log encoded as a MultipartFile
     * @throws McpBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/logo",
            method = RequestMethod.POST)
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> createLogoPost(HttpServletRequest request, @PathVariable String orgMrn, @RequestParam("logo") MultipartFile logo) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            if (org.getLogo() != null) {
                throw new McpBasicRestException(HttpStatus.CONFLICT, MCPIdRegConstants.LOGO_ALREADY_EXISTS, request.getServletPath());
            }
            try {
                this.updateLogo(org, logo.getInputStream());
                organizationService.save(org);
                return new ResponseEntity<>(HttpStatus.CREATED);
            } catch (IOException e) {
                log.error("Unable to create logo", e);
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.INVALID_IMAGE, request.getServletPath());
            }
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns info about the logo identified by the given ID
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/logo",
            method = RequestMethod.GET)
    @ResponseBody
    public ResponseEntity<?> getLogo(HttpServletRequest request, @PathVariable String orgMrn) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            if (org.getLogo() != null) {
                byte[] image = org.getLogo().getImage();
                HttpHeaders responseHeaders = new HttpHeaders();
                responseHeaders.setContentLength(image.length);
                responseHeaders.setContentType(MediaType.IMAGE_PNG);
                return new ResponseEntity<>(image, responseHeaders, HttpStatus.OK);
            } else {
                throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.LOGO_NOT_FOUND, request.getServletPath());
            }
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }

    }

    /**
     * Creates or updates a logo for an organization
     * @param request so we can get the servlet path
     * @param orgMrn the resource
     * @param logo the logo bytes
     * @throws McpBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/logo",
            method = RequestMethod.PUT)
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> updateLogoPut(HttpServletRequest request, @PathVariable String orgMrn, @RequestBody byte[] logo) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            try {
                ByteArrayInputStream inputLogo = new ByteArrayInputStream(logo);
                this.updateLogo(org, inputLogo);
                organizationService.save(org);
            } catch (IOException e) {
                log.error("Unable to create or update logo", e);
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.INVALID_IMAGE, request.getServletPath());
            }
            return new ResponseEntity<>(HttpStatus.CREATED);
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }
    /**
     * Deletes a Logo
     *
     * @return a reply...
     * @throws McpBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/logo",
            method = RequestMethod.DELETE)
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> deleteLogo(HttpServletRequest request, @PathVariable String orgMrn) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            if (org.getLogo() != null) {
                org.setLogo(null);
                organizationService.save(org);
            }
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            throw new McpBasicRestException(HttpStatus.NOT_FOUND, MCPIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }
    // this method belongs to on the Organization class, not as a free function in the controller
    private void updateLogo(Organization org, InputStream logoInputStream) throws IOException {
        ByteArrayOutputStream newImage = ImageUtil.resize(logoInputStream);
        if (org.getLogo() != null) {
            org.getLogo().setImage(newImage.toByteArray());
        } else {
            Logo newLogo = new Logo();
            newLogo.setImage(newImage.toByteArray());
            newImage.close();
            newLogo.setOrganization(org);
            org.setLogo(newLogo);
        }
    }
}
