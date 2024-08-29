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

import io.swagger.v3.oas.annotations.Operation;
import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.identityregistry.exception.McpBasicRestException;
import net.maritimeconnectivity.identityregistry.model.database.Logo;
import net.maritimeconnectivity.identityregistry.model.database.Organization;
import net.maritimeconnectivity.identityregistry.services.OrganizationService;
import net.maritimeconnectivity.identityregistry.utils.ImageUtil;
import net.maritimeconnectivity.identityregistry.utils.MCPIdRegConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import jakarta.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;

@RestController
@RequestMapping(value = {"oidc", "x509"})
@Slf4j
public class LogoController {

    private OrganizationService organizationService;

    /**
     * Creates a logo for an organization
     *
     * @param request request to get servletPath
     * @param orgMrn  resource location for organization
     * @param logo    the log encoded as a MultipartFile
     * @throws McpBasicRestException
     */
    @PostMapping(
            value = "/api/org/{orgMrn}/logo",
            consumes = {MediaType.IMAGE_PNG_VALUE, MediaType.IMAGE_JPEG_VALUE}
    )
    @Operation(
            description = "Create a new organization logo using POST"
    )
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'ORG_ADMIN')")
    public ResponseEntity<?> createLogoPost(HttpServletRequest request, @PathVariable String orgMrn, @RequestParam("logo") MultipartFile logo) throws McpBasicRestException {
        Organization org = this.organizationService.getOrganizationByMrn(orgMrn);
        if (org != null) {
            if (org.getLogo() != null) {
                throw new McpBasicRestException(HttpStatus.CONFLICT, MCPIdRegConstants.LOGO_ALREADY_EXISTS, request.getServletPath());
            }
            HttpHeaders headers = new HttpHeaders();
            try {
                this.updateLogo(org, logo.getInputStream());
                organizationService.save(org);
                String path = request.getRequestURL().toString();
                headers.setLocation(new URI(path));
            } catch (IOException | DataIntegrityViolationException e) {
                log.error("Unable to create logo", e);
                throw new McpBasicRestException(HttpStatus.BAD_REQUEST, MCPIdRegConstants.INVALID_IMAGE, request.getServletPath());
            } catch (URISyntaxException e) {
                log.error("Could not create Location header", e);
            }
            return new ResponseEntity<>(headers, HttpStatus.CREATED);
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
    @GetMapping(
            value = "/api/org/{orgMrn}/logo",
            produces = {MediaType.IMAGE_PNG_VALUE, MediaType.APPLICATION_JSON_VALUE}
    )
    @Operation(
            description = "Get the logo of the given organization"
    )
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
     *
     * @param request so we can get the servlet path
     * @param orgMrn  the resource
     * @param logo    the logo bytes
     * @throws McpBasicRestException
     */
    @PutMapping(
            value = "/api/org/{orgMrn}/logo",
            consumes = {MediaType.IMAGE_PNG_VALUE, MediaType.IMAGE_JPEG_VALUE}
    )
    @Operation(
            description = "Update an existing organization logo or create it if none already exists"
    )
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'ORG_ADMIN')")
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
    @DeleteMapping(
            value = "/api/org/{orgMrn}/logo"
    )
    @Operation(
            description = "Delete an organization logo"
    )
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn, 'ORG_ADMIN')")
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

    @Autowired
    public void setOrganizationService(OrganizationService organizationService) {
        this.organizationService = organizationService;
    }
}
