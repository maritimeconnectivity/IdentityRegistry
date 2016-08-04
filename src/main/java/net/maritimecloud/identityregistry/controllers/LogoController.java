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
import net.maritimecloud.identityregistry.model.database.Logo;
import net.maritimecloud.identityregistry.model.database.Organization;
import net.maritimecloud.identityregistry.services.OrganizationService;
import net.maritimecloud.identityregistry.utils.ImageUtil;
import net.maritimecloud.identityregistry.utils.MCIdRegConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import java.io.*;

@RestController
@RequestMapping(value={"oidc", "x509"})
public class LogoController {

    private OrganizationService organizationService;

    @Autowired
    public void setOrganizationService(OrganizationService organizationService) {
        this.organizationService = organizationService;
    }

    /**
     * Creates or updates a logo for an organization
     * @param request
     * @param orgShortName
     * @param logo
     * @return
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/logo",
            method = RequestMethod.POST)
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<?> createLogoPost(HttpServletRequest request, @PathVariable String orgShortName, @RequestParam("logo") MultipartFile logo) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            try {
                this.saveLogo(org, logo.getInputStream());
                organizationService.save(org);
            } catch (IOException e) {
                e.printStackTrace();
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.INVALID_IMAGE, request.getServletPath());
            }
            return new ResponseEntity<>(HttpStatus.ACCEPTED);
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns info about the logo identified by the given ID
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/logo",
            method = RequestMethod.GET,
            produces = "image/png")
    @ResponseBody
    public ResponseEntity<?> getLogo(HttpServletRequest request, @PathVariable String orgShortName) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null && org.getLogo() != null) {
            return new ResponseEntity<>(org.getLogo().getImage(), HttpStatus.OK);
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }

    }

    /**
     * Creates or updates a logo for an organization
     * @param request
     * @param orgShortName
     * @param logo
     * @return
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/logo",
            method = RequestMethod.PUT)
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<?> createLogoPut(HttpServletRequest request, @PathVariable String orgShortName, @RequestBody byte[] logo) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            try {
                ByteArrayInputStream inputLogo = new ByteArrayInputStream(logo);
                this.saveLogo(org, inputLogo);
                organizationService.save(org);
            } catch (IOException e) {
                e.printStackTrace();
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.INVALID_IMAGE, request.getServletPath());
            }
            return new ResponseEntity<>(HttpStatus.ACCEPTED);
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }
    /**
     * Deletes a Logo
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/logo",
            method = RequestMethod.DELETE)
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<?> deleteLogo(HttpServletRequest request, @PathVariable String orgShortName) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            if (org.getLogo() != null) {
                org.setLogo(null);
                organizationService.save(org);
            }
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    private void saveLogo(Organization org, InputStream logoInputStream) throws IOException {
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
