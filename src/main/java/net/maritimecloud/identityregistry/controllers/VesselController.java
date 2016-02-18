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

import org.springframework.web.bind.annotation.RestController;

import net.maritimecloud.identityregistry.model.Certificate;
import net.maritimecloud.identityregistry.model.Organization;
import net.maritimecloud.identityregistry.model.User;
import net.maritimecloud.identityregistry.model.Vessel;
import net.maritimecloud.identityregistry.services.CertificateService;
import net.maritimecloud.identityregistry.services.OrganizationService;
import net.maritimecloud.identityregistry.services.VesselService;
import net.maritimecloud.identityregistry.utils.AccessControlUtil;
import net.maritimecloud.identityregistry.utils.CertificateUtil;
import net.maritimecloud.identityregistry.utils.MCIdRegConstants;

import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
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
@RequestMapping(value={"admin", "oidc", "x509"})
public class VesselController {
    private VesselService vesselService;

    private OrganizationService organizationService;

    private CertificateService certificateService;

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
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/vessel",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<?> createVessel(HttpServletRequest request, @PathVariable String orgShortName, @RequestBody Vessel input) {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(org.getName(), orgShortName)) {
                input.setIdOrganization(org.getId().intValue());
                Vessel newVessel = this.vesselService.saveVessel(input);
                return new ResponseEntity<Vessel>(newVessel, HttpStatus.OK);
            }
            return new ResponseEntity<>(MCIdRegConstants.MISSING_RIGHTS, HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(MCIdRegConstants.ORG_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Returns info about the vessel identified by the given ID
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/vessel/{vesselId}",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<?> getVessel(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long vesselId) {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(org.getName(), orgShortName)) {
                Vessel vessel = this.vesselService.getVesselById(vesselId);
                if (vessel == null) {
                    return new ResponseEntity<>(MCIdRegConstants.VESSEL_NOT_FOUND, HttpStatus.NOT_FOUND);
                }
                if (vessel.getIdOrganization() == org.getId().intValue()) {
                    return new ResponseEntity<Vessel>(vessel, HttpStatus.OK);
                }
            }
            return new ResponseEntity<>(MCIdRegConstants.MISSING_RIGHTS, HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(MCIdRegConstants.ORG_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Updates a Vessel
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/vessel/{vesselId}",
            method = RequestMethod.PUT)
    @ResponseBody
    public ResponseEntity<?> updateVessel(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long vesselId, @RequestBody Vessel input) {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(org.getName(), orgShortName)) {
                Vessel vessel = this.vesselService.getVesselById(vesselId);
                if (vessel == null) {
                    return new ResponseEntity<>(MCIdRegConstants.VESSEL_NOT_FOUND, HttpStatus.NOT_FOUND);
                }
                if (vessel.getId() == input.getId() && vessel.getIdOrganization() == org.getId().intValue()) {
                    input.copyTo(vessel);
                    this.vesselService.saveVessel(vessel);
                    return new ResponseEntity<>(HttpStatus.OK);
                }
            }
            return new ResponseEntity<>(MCIdRegConstants.MISSING_RIGHTS, HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(MCIdRegConstants.ORG_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Deletes a Vessel
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/vessel/{vesselId}",
            method = RequestMethod.DELETE)
    @ResponseBody
    public ResponseEntity<?> deleteVessel(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long vesselId) {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(org.getName(), orgShortName)) {
                Vessel vessel = this.vesselService.getVesselById(vesselId);
                if (vessel == null) {
                    return new ResponseEntity<>(MCIdRegConstants.VESSEL_NOT_FOUND, HttpStatus.NOT_FOUND);
                }
                if (vessel.getIdOrganization() == org.getId().intValue()) {
                    this.vesselService.deleteVessel(vesselId);
                    return new ResponseEntity<>(HttpStatus.OK);
                }
            }
            return new ResponseEntity<>(MCIdRegConstants.MISSING_RIGHTS, HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(MCIdRegConstants.ORG_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Returns a list of vessels owned by the organization identified by the given ID
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/vessels",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<?> getOrganizationVessels(HttpServletRequest request, @PathVariable String orgShortName) {
        // Enable filters on certificates to filter out revoked and outdated certificates
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(org.getName(), orgShortName)) {
                List<Vessel> vessels = this.vesselService.listOrgVessels(org.getId().intValue());
                return new ResponseEntity<List<Vessel>>(vessels, HttpStatus.OK);
            }
            return new ResponseEntity<>(MCIdRegConstants.MISSING_RIGHTS, HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(MCIdRegConstants.ORG_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Returns new certificate for the vessel identified by the given ID
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/vessel/{vesselId}/generatecertificate",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<?> newVesselCert(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long vesselId) {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(org.getName(), orgShortName)) {
                Vessel vessel = this.vesselService.getVesselById(vesselId);
                if (vessel == null) {
                    return new ResponseEntity<>(MCIdRegConstants.VESSEL_NOT_FOUND, HttpStatus.NOT_FOUND);
                }
                if (vessel.getIdOrganization() == org.getId().intValue()) {
                    // Create the certificate and save it so that it gets an id that can be use as certificate serialnumber
                    Certificate newMCCert = new Certificate();
                    newMCCert.setVessel(vessel);
                    newMCCert = this.certificateService.saveCertificate(newMCCert);
                    // Generate keypair for vessel
                    KeyPair vesselKeyPair = CertificateUtil.generateKeyPair();
                    X509Certificate vesselCert = CertificateUtil.generateCertForEntity(newMCCert.getId(), org.getCountry(), org.getName(), vessel.getName(), vessel.getName(), "", vesselKeyPair.getPublic());
                    String pemCertificate = "";
                    try {
                        pemCertificate = CertificateUtil.getPemFromEncoded("CERTIFICATE", vesselCert.getEncoded());
                    } catch (CertificateEncodingException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                    String pemPublicKey = CertificateUtil.getPemFromEncoded("PUBLIC KEY", vesselKeyPair.getPublic().getEncoded());
                    String pemPrivateKey = CertificateUtil.getPemFromEncoded("PRIVATE KEY", vesselKeyPair.getPrivate().getEncoded());
                    newMCCert.setCertificate(pemCertificate);
                    newMCCert.setStart(vesselCert.getNotBefore());
                    newMCCert.setEnd(vesselCert.getNotAfter());
                    this.certificateService.saveCertificate(newMCCert);
                    String jsonReturn = "{ \"publickey\":\"" + pemPublicKey + "\", \"privatekey\":\"" + pemPrivateKey + "\", \"certificate\":\"" + pemCertificate + "\"  }";

                    return new ResponseEntity<String>(jsonReturn, HttpStatus.OK);
                }
            }
            return new ResponseEntity<>(MCIdRegConstants.MISSING_RIGHTS, HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(MCIdRegConstants.ORG_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Revokes certificate for the vessel identified by the given ID
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/vessel/{vesselId}/revokecertificate/{certId}",
            method = RequestMethod.DELETE,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<?> revokeVesselCert(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long vesselId, @PathVariable Long certId) {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the vessel has the needed rights
            if (AccessControlUtil.hasAccessToOrg(org.getName(), orgShortName)) {
                Vessel vessel = this.vesselService.getVesselById(vesselId);
                if (vessel == null) {
                    return new ResponseEntity<>(MCIdRegConstants.VESSEL_NOT_FOUND, HttpStatus.NOT_FOUND);
                }
                if (vessel.getIdOrganization() == org.getId().intValue()) {
                    Certificate cert = this.certificateService.getCertificateById(certId);
                    Vessel certVessel = cert.getVessel();
                    if (certVessel != null && certVessel.getId().equals(vessel.getId())) {
                        cert.setRevoked(true);
                        this.certificateService.saveCertificate(cert);
                        return new ResponseEntity<>(HttpStatus.OK);
                    }
                }
            }
            return new ResponseEntity<>(MCIdRegConstants.MISSING_RIGHTS, HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(MCIdRegConstants.ORG_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

}
