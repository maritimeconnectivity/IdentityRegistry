/*
 * Copyright 2017 Danish Maritime Authority
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

import lombok.extern.slf4j.Slf4j;
import net.maritimecloud.identityregistry.exception.McBasicRestException;
import net.maritimecloud.identityregistry.model.database.VesselImage;
import net.maritimecloud.identityregistry.model.database.entities.Vessel;
import net.maritimecloud.identityregistry.services.VesselServiceImpl;
import net.maritimecloud.identityregistry.utils.ImageUtil;
import net.maritimecloud.identityregistry.utils.MCIdRegConstants;
import org.springframework.beans.factory.annotation.Autowired;
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
public class VesselImageController {

    private VesselServiceImpl vesselService;

    @Autowired
    public void setVesselService(VesselServiceImpl vesselService) {
        this.vesselService = vesselService;
    }

    /**
     * Creates or updates an image for a vessel
     * @param request
     * @param orgMrn
     * @param vesselMrn
     * @param image
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/vessel/{vesselMrn}/vesselImage",
            method = RequestMethod.POST
    )
    @ResponseBody
    @PreAuthorize("hasRole('VESSEL_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> createVesselImagePost(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String vesselMrn, @RequestParam("image") MultipartFile image) throws McBasicRestException {
        Vessel vessel = this.vesselService.getByMrn(vesselMrn);
        if (vessel != null) {
            try {
                this.updateVesselImage(vessel, image.getInputStream());
                vesselService.save(vessel);
                return new ResponseEntity<>(HttpStatus.CREATED);
            } catch (IOException e) {
                log.error("Unable to create vessel image", e);
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.INVALID_IMAGE, request.getServletPath());
            }
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.VESSEL_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Creates or updates an image for a vessel
     * @param request
     * @param orgMrn
     * @param vesselMrn
     * @param image
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/vessel/{vesselMrn}/vesselImage",
            method = RequestMethod.PUT
    )
    @ResponseBody
    @PreAuthorize("hasRole('VESSEL_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> createVesselImagePut(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String vesselMrn, @RequestBody byte[] image) throws McBasicRestException {
        Vessel vessel = this.vesselService.getByMrn(vesselMrn);
        if (vessel != null) {
            try {
                ByteArrayInputStream inputImage = new ByteArrayInputStream(image);
                this.updateVesselImage(vessel, inputImage);
                vesselService.save(vessel);
                return new ResponseEntity<>(HttpStatus.CREATED);
            } catch (IOException e) {
                log.error("Unable to create vessel image", e);
                throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.INVALID_IMAGE, request.getServletPath());
            }
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.VESSEL_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns the image of the vessel given by the ID
     * @param request
     * @param orgMrn
     * @param vesselMrn
     * @return a PNG image
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/vessel/{vesselMrn}/vesselImage",
            method = RequestMethod.GET
    )
    @ResponseBody
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> getVesselImage(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String vesselMrn) throws McBasicRestException {
        Vessel vessel = this.vesselService.getByMrn(vesselMrn);
        if (vessel != null) {
            if (vessel.getImage() != null) {
                byte[] image = vessel.getImage().getImage();
                return new ResponseEntity<>(image, HttpStatus.OK);
            } else {
                throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.VESSEL_IMAGE_NOT_FOUND, request.getServletPath());
            }
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.VESSEL_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Deletes the image for the vessel given by the ID
     * @param request
     * @param orgMrn
     * @param vesselMrn
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/vessel/{vesselMrn}/vesselImage",
            method = RequestMethod.DELETE
    )
    @ResponseBody
    @PreAuthorize("hasRole('VESSEL_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> deleteVesselImage(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String vesselMrn) throws McBasicRestException {
        Vessel vessel = this.vesselService.getByMrn(vesselMrn);
        if (vessel != null) {
            if (vessel.getImage() != null) {
                vessel.setImage(null);
                this.vesselService.save(vessel);
            }
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.VESSEL_NOT_FOUND, request.getServletPath());
        }
    }

    private void updateVesselImage(Vessel vessel, InputStream imageInputStream) throws IOException {
        ByteArrayOutputStream newImage = ImageUtil.resize(imageInputStream);
        if (vessel.getImage() != null) {
            vessel.getImage().setImage(newImage.toByteArray());
        } else {
            VesselImage newVesselImage = new VesselImage();
            newVesselImage.setImage(newImage.toByteArray());
            newImage.close();
            newVesselImage.setVessel(vessel);
            vessel.setImage(newVesselImage);
        }
    }
}
