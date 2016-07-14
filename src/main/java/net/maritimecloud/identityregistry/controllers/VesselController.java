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
import org.springframework.web.bind.annotation.RestController;

import net.maritimecloud.identityregistry.exception.McBasicRestException;
import net.maritimecloud.identityregistry.model.database.Certificate;
import net.maritimecloud.identityregistry.model.data.CertificateRevocation;
import net.maritimecloud.identityregistry.model.database.Organization;
import net.maritimecloud.identityregistry.model.data.PemCertificate;
import net.maritimecloud.identityregistry.model.database.entities.Vessel;
import net.maritimecloud.identityregistry.model.database.entities.VesselAttribute;
import net.maritimecloud.identityregistry.services.CertificateService;
import net.maritimecloud.identityregistry.services.OrganizationService;
import net.maritimecloud.identityregistry.services.VesselService;
import net.maritimecloud.identityregistry.utils.AccessControlUtil;
import net.maritimecloud.identityregistry.utils.CertificateUtil;
import net.maritimecloud.identityregistry.utils.MCIdRegConstants;

import java.util.HashMap;
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
public class VesselController extends  BaseControllerWithCertificate{
    private VesselService vesselService;

    private OrganizationService organizationService;

    private CertificateService certificateService;

    private static final Logger logger = LoggerFactory.getLogger(VesselController.class);

    @Autowired
    private CertificateUtil certUtil;

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setOrganizationService(OrganizationService organizationService) {
        this.organizationService = organizationService;
    }

    @Autowired
    public void setVesselService(VesselService organizationService) {
        this.vesselService = organizationService;
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
    public ResponseEntity<Vessel> createVessel(HttpServletRequest request, @PathVariable String orgShortName, @RequestBody Vessel input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                input.setIdOrganization(org.getId());
                Vessel newVessel = this.vesselService.saveVessel(input);
                return new ResponseEntity<Vessel>(newVessel, HttpStatus.OK);
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
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
    public ResponseEntity<Vessel> getVessel(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long vesselId) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                Vessel vessel = this.vesselService.getVesselById(vesselId);
                if (vessel == null) {
                    throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.VESSEL_NOT_FOUND, request.getServletPath());
                }
                if (vessel.getIdOrganization().compareTo(org.getId()) == 0) {
                    return new ResponseEntity<Vessel>(vessel, HttpStatus.OK);
                }
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
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
    public ResponseEntity<?> updateVessel(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long vesselId, @RequestBody Vessel input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                Vessel vessel = this.vesselService.getVesselById(vesselId);
                if (vessel == null) {
                    throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.VESSEL_NOT_FOUND, request.getServletPath());
                }
                if (vessel.getId().compareTo(input.getId()) == 0 && vessel.getIdOrganization().compareTo(org.getId()) == 0) {
                    input.selectiveCopyTo(vessel);
                    this.vesselService.saveVessel(vessel);
                    return new ResponseEntity<>(HttpStatus.OK);
                }
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
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
    public ResponseEntity<?> deleteVessel(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long vesselId) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                Vessel vessel = this.vesselService.getVesselById(vesselId);
                if (vessel == null) {
                    throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.VESSEL_NOT_FOUND, request.getServletPath());
                }
                if (vessel.getIdOrganization().compareTo(org.getId()) == 0) {
                    this.vesselService.deleteVessel(vesselId);
                    return new ResponseEntity<>(HttpStatus.OK);
                }
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
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
    public ResponseEntity<List<Vessel>> getOrganizationVessels(HttpServletRequest request, @PathVariable String orgShortName) throws McBasicRestException {
        // Enable filters on certificates to filter out revoked and outdated certificates
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                List<Vessel> vessels = this.vesselService.listOrgVessels(org.getId());
                return new ResponseEntity<List<Vessel>>(vessels, HttpStatus.OK);
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
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
    public ResponseEntity<PemCertificate> newVesselCert(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long vesselId) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                Vessel vessel = this.vesselService.getVesselById(vesselId);
                if (vessel == null) {
                    throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.VESSEL_NOT_FOUND, request.getServletPath());
                }
                if (vessel.getIdOrganization().compareTo(org.getId()) == 0) {
                    PemCertificate ret = this.issueCertificate(vessel, org, "vessel");
                    return new ResponseEntity<PemCertificate>(ret, HttpStatus.OK);
                }
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
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
    public ResponseEntity<?> revokeVesselCert(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long vesselId, @PathVariable Long certId,  @RequestBody CertificateRevocation input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the vessel has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                Vessel vessel = this.vesselService.getVesselById(vesselId);
                if (vessel == null) {
                    throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.VESSEL_NOT_FOUND, request.getServletPath());
                }
                if (vessel.getIdOrganization().compareTo(org.getId()) == 0) {
                    Certificate cert = this.certificateService.getCertificateById(certId);
                    Vessel certVessel = cert.getVessel();
                    if (certVessel != null && certVessel.getId().compareTo(vessel.getId()) == 0) {
                        this.revokeCertificate(certId, input, request);
                        return new ResponseEntity<>(HttpStatus.OK);
                    }
                }
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
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
                case "imo number":
                    attrs.put(CertificateUtil.MC_OID_IMO_NUMBER, attr.getAttributeValue());
                    break;
                case "mmsi number":
                    attrs.put(CertificateUtil.MC_OID_MMSI_NUMBER, attr.getAttributeValue());
                    break;
                case "flagstate":
                    attrs.put(CertificateUtil.MC_OID_FLAGSTATE, attr.getAttributeValue());
                    break;
                default:
                    logger.debug("Unexpected attribute value: " + attrName);
            }
        }
        return attrs;
    }
}
