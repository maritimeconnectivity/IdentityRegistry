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

import net.maritimecloud.identityregistry.model.database.CertificateModel;
import net.maritimecloud.identityregistry.services.EntityService;
import net.maritimecloud.identityregistry.utils.ValidateUtil;
import net.maritimecloud.identityregistry.validators.VesselValidator;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.ServletRequestDataBinder;
import org.springframework.web.bind.annotation.*;

import net.maritimecloud.identityregistry.exception.McBasicRestException;
import net.maritimecloud.identityregistry.model.database.Certificate;
import net.maritimecloud.identityregistry.model.data.CertificateRevocation;
import net.maritimecloud.identityregistry.model.data.PemCertificate;
import net.maritimecloud.identityregistry.model.database.entities.Vessel;
import net.maritimecloud.identityregistry.model.database.entities.VesselAttribute;
import net.maritimecloud.identityregistry.utils.CertificateUtil;

import java.util.HashMap;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
public class VesselController extends EntityController<Vessel> {
    private static final Logger logger = LoggerFactory.getLogger(VesselController.class);

    @Autowired
    public void setVesselService(EntityService<Vessel> vesselService) {
        this.entityService = vesselService;
    }

    @Autowired
    private VesselValidator vesselValidator;

    @InitBinder
    protected void initBinder(final HttpServletRequest request, final ServletRequestDataBinder binder) {
        binder.addValidators(vesselValidator);
    }

    /**
     * Creates a new Vessel
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/vessel",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<Vessel> createVessel(HttpServletRequest request, @PathVariable String orgShortName, @Validated @RequestBody Vessel input, BindingResult bindingResult) throws McBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        return this.createEntity(request, orgShortName, input);
    }

    /**
     * Returns info about the vessel identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/vessel/{vesselId}",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<Vessel> getVessel(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long vesselId) throws McBasicRestException {
        return this.getEntity(request, orgShortName, vesselId);
    }

    /**
     * Updates a Vessel
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/vessel/{vesselId}",
            method = RequestMethod.PUT)
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<?> updateVessel(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long vesselId, @Validated @RequestBody Vessel input, BindingResult bindingResult) throws McBasicRestException {
        ValidateUtil.hasErrors(bindingResult, request);
        return this.updateEntity(request, orgShortName, vesselId, input);
    }

    /**
     * Deletes a Vessel
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/vessel/{vesselId}",
            method = RequestMethod.DELETE)
    @ResponseBody
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<?> deleteVessel(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long vesselId) throws McBasicRestException {
        return this.deleteEntity(request, orgShortName, vesselId);
    }

    /**
     * Returns a list of vessels owned by the organization identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/vessels",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("@accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<List<Vessel>> getOrganizationVessels(HttpServletRequest request, @PathVariable String orgShortName) throws McBasicRestException {
        return this.getOrganizationEntities(request, orgShortName);
    }

    /**
     * Returns new certificate for the vessel identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/vessel/{vesselId}/generatecertificate",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<PemCertificate> newVesselCert(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long vesselId) throws McBasicRestException {
        return this.newEntityCert(request, orgShortName, vesselId, "vessel");
    }

    /**
     * Revokes certificate for the vessel identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/vessel/{vesselId}/certificates/{certId}/revoke",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @PreAuthorize("hasRole('ORG_ADMIN') and @accessControlUtil.hasAccessToOrg(#orgShortName)")
    public ResponseEntity<?> revokeVesselCert(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long vesselId, @PathVariable Long certId,  @RequestBody CertificateRevocation input) throws McBasicRestException {
        return this.revokeEntityCert(request, orgShortName, vesselId, certId, input);
    }

    protected HashMap<String, String> getAttr(CertificateModel certOwner) {
        HashMap<String, String> attrs = super.getAttr(certOwner);
        // Find special MC attributes to put in the certificate
        Vessel vessel = (Vessel) certOwner;
        // Look in the vessel attributes too
        for (VesselAttribute attr : vessel.getAttributes()) {
            String attrName = attr.getAttributeName().toLowerCase();
            switch(attrName) {
                case "callsign":
                    attrs.put(CertificateUtil.MC_OID_CALLSIGN, attr.getAttributeValue());
                    break;
                case "imo-number":
                    attrs.put(CertificateUtil.MC_OID_IMO_NUMBER, attr.getAttributeValue());
                    break;
                case "mmsi-number":
                    attrs.put(CertificateUtil.MC_OID_MMSI_NUMBER, attr.getAttributeValue());
                    break;
                case "flagstate":
                    attrs.put(CertificateUtil.MC_OID_FLAGSTATE, attr.getAttributeValue());
                    break;
                case "ais-class":
                    attrs.put(CertificateUtil.MC_OID_AIS_SHIPTYPE, attr.getAttributeValue());
                    break;
                case "port-of-register":
                    attrs.put(CertificateUtil.MC_OID_PORT_OF_REGISTER, attr.getAttributeValue());
                    break;
                default:
                    logger.debug("Unexpected attribute value: " + attrName);
            }
        }
        return attrs;
    }

    @Override
    protected Vessel getCertEntity(Certificate cert) {
        return cert.getVessel();
    }
}
