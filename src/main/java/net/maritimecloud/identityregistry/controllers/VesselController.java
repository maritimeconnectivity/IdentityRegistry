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
package net.maritimecloud.identityregistry.controllers;

import net.maritimecloud.identityregistry.exception.McBasicRestException;
import net.maritimecloud.identityregistry.model.data.CertificateBundle;
import net.maritimecloud.identityregistry.model.data.CertificateRevocation;
import net.maritimecloud.identityregistry.model.database.Certificate;
import net.maritimecloud.identityregistry.model.database.CertificateModel;
import net.maritimecloud.identityregistry.model.database.entities.Service;
import net.maritimecloud.identityregistry.model.database.entities.Vessel;
import net.maritimecloud.identityregistry.services.EntityService;
import net.maritimecloud.identityregistry.utils.AttributesUtil;
import net.maritimecloud.identityregistry.utils.MCIdRegConstants;
import net.maritimecloud.identityregistry.utils.MrnUtil;
import net.maritimecloud.identityregistry.utils.ValidateUtil;
import net.maritimecloud.identityregistry.validators.VesselValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.ServletRequestDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Set;

@RestController
public class VesselController extends EntityController<Vessel> {
    private static final Logger logger = LoggerFactory.getLogger(VesselController.class);

    @Autowired
    public void setVesselService(EntityService<Vessel> vesselService) {
        this.entityService = vesselService;
    }

    @Autowired
    private VesselValidator vesselValidator;

    @InitBinder("vessel")
    protected void initBinder(final ServletRequestDataBinder binder) {
        binder.addValidators(vesselValidator);
    }

    /**
     * Creates a new Vessel
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/vessel",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    @PreAuthorize("hasRole('VESSEL_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<Vessel> createVessel(HttpServletRequest request, @PathVariable String orgMrn, @Validated @RequestBody Vessel input, BindingResult bindingResult) throws McBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        return this.createEntity(request, orgMrn, input);
    }

    /**
     * Returns info about the vessel identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/vessel/{vesselMrn}",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<Vessel> getVessel(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String vesselMrn) throws McBasicRestException {
        return this.getEntity(request, orgMrn, vesselMrn);
    }

    /**
     * Updates a Vessel
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/vessel/{vesselMrn}",
            method = RequestMethod.PUT)
    @ResponseBody
    @PreAuthorize("hasRole('VESSEL_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> updateVessel(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String vesselMrn, @Validated @RequestBody Vessel input, BindingResult bindingResult) throws McBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        return this.updateEntity(request, orgMrn, vesselMrn, input);
    }

    /**
     * Returns the set of services that has a relation with a specific vessel
     *
     * @return a reply...
     * @throws McBasicRestException
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/vessel/{vesselMrn}/services",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8"
    )
    @ResponseBody
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<Set<Service>> getVesselServices(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String vesselMrn) throws McBasicRestException {
        if (!MrnUtil.getOrgShortNameFromOrgMrn(orgMrn).equalsIgnoreCase(MrnUtil.getOrgShortNameFromEntityMrn(vesselMrn))) {
            throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        }
        Vessel vessel = this.entityService.getByMrn(vesselMrn);
        Set<Service> services = vessel.getServices();
        return new ResponseEntity<>(services, HttpStatus.OK);
    }

    /**
     * Deletes a Vessel
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/vessel/{vesselMrn}",
            method = RequestMethod.DELETE)
    @ResponseBody
    @PreAuthorize("hasRole('VESSEL_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> deleteVessel(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String vesselMrn) throws McBasicRestException {
        return this.deleteEntity(request, orgMrn, vesselMrn);
    }

    /**
     * Returns a list of vessels owned by the organization identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/vessels",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgMrn)")
    public Page<Vessel> getOrganizationVessels(HttpServletRequest request, @PathVariable String orgMrn, Pageable pageable) throws McBasicRestException {
        return this.getOrganizationEntities(request, orgMrn, pageable);
    }

    /**
     * Returns new certificate for the vessel identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/vessel/{vesselMrn}/certificate/issue-new",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("hasRole('VESSEL_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<CertificateBundle> newVesselCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String vesselMrn) throws McBasicRestException {
        return this.newEntityCert(request, orgMrn, vesselMrn, "vessel");
    }

    /**
     * Revokes certificate for the vessel identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgMrn}/vessel/{vesselMrn}/certificate/{certId}/revoke",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("hasRole('VESSEL_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgMrn)")
    public ResponseEntity<?> revokeVesselCert(HttpServletRequest request, @PathVariable String orgMrn, @PathVariable String vesselMrn, @PathVariable BigInteger certId, @Valid @RequestBody CertificateRevocation input) throws McBasicRestException {
        return this.revokeEntityCert(request, orgMrn, vesselMrn, certId, input);
    }

    protected HashMap<String, String> getAttr(CertificateModel certOwner) {
        HashMap<String, String> attrs = super.getAttr(certOwner);
        // Find special MC attributes to put in the certificate
        attrs.putAll(AttributesUtil.getAttributes(certOwner));

        return attrs;
    }

    @Override
    protected Vessel getCertEntity(Certificate cert) {
        return cert.getVessel();
    }
}
