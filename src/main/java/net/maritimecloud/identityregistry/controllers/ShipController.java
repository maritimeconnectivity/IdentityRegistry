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

import net.maritimecloud.identityregistry.model.Certificate;
import net.maritimecloud.identityregistry.model.Organization;
import net.maritimecloud.identityregistry.model.Ship;
import net.maritimecloud.identityregistry.services.CertificateService;
import net.maritimecloud.identityregistry.services.OrganizationService;
import net.maritimecloud.identityregistry.services.ShipService;
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
public class ShipController {
    private ShipService shipService;

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
    public void setShipService(ShipService organizationService) {
        this.shipService = organizationService;
    }

    /**
     * Creates a new Ship
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/ship",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<?> createShip(HttpServletRequest request, @PathVariable String orgShortName, @RequestBody Ship input) {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                input.setIdOrganization(org.getId().intValue());
                Ship newShip = this.shipService.saveShip(input);
                return new ResponseEntity<Ship>(newShip, HttpStatus.OK);
            }
            return new ResponseEntity<>(MCIdRegConstants.MISSING_RIGHTS, HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(MCIdRegConstants.ORG_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Returns info about the ship identified by the given ID
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/ship/{shipId}",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<?> getShip(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long shipId) {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                Ship ship = this.shipService.getShipById(shipId);
                if (ship == null) {
                    return new ResponseEntity<>(MCIdRegConstants.SHIP_NOT_FOUND, HttpStatus.NOT_FOUND);
                }
                if (ship.getIdOrganization() == org.getId().intValue()) {
                    return new ResponseEntity<Ship>(ship, HttpStatus.OK);
                }
            }
            return new ResponseEntity<>(MCIdRegConstants.MISSING_RIGHTS, HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(MCIdRegConstants.ORG_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Updates a Ship
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/ship/{shipId}",
            method = RequestMethod.PUT)
    @ResponseBody
    public ResponseEntity<?> updateShip(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long shipId, @RequestBody Ship input) {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                Ship ship = this.shipService.getShipById(shipId);
                if (ship == null) {
                    return new ResponseEntity<>(MCIdRegConstants.SHIP_NOT_FOUND, HttpStatus.NOT_FOUND);
                }
                if (ship.getId() == input.getId() && ship.getIdOrganization() == org.getId().intValue()) {
                    input.copyTo(ship);
                    this.shipService.saveShip(ship);
                    return new ResponseEntity<>(HttpStatus.OK);
                }
            }
            return new ResponseEntity<>(MCIdRegConstants.MISSING_RIGHTS, HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(MCIdRegConstants.ORG_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Deletes a Ship
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/ship/{shipId}",
            method = RequestMethod.DELETE)
    @ResponseBody
    public ResponseEntity<?> deleteShip(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long shipId) {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                Ship ship = this.shipService.getShipById(shipId);
                if (ship == null) {
                    return new ResponseEntity<>(MCIdRegConstants.SHIP_NOT_FOUND, HttpStatus.NOT_FOUND);
                }
                if (ship.getIdOrganization() == org.getId().intValue()) {
                    this.shipService.deleteShip(shipId);
                    return new ResponseEntity<>(HttpStatus.OK);
                }
            }
            return new ResponseEntity<>(MCIdRegConstants.MISSING_RIGHTS, HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(MCIdRegConstants.ORG_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Returns a list of ships owned by the organization identified by the given ID
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/ships",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<?> getOrganizationShips(HttpServletRequest request, @PathVariable String orgShortName) {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                List<Ship> ships = this.shipService.listOrgShips(org.getId().intValue());
                return new ResponseEntity<List<Ship>>(ships, HttpStatus.OK);
            }
            return new ResponseEntity<>(MCIdRegConstants.MISSING_RIGHTS, HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(MCIdRegConstants.ORG_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Returns new certificate for the ship identified by the given ID
     * 
     * @return a reply...
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/ship/{shipId}/generatecertificate",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<?> newOrgCert(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long shipId) {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the user has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                Ship ship = this.shipService.getShipById(shipId);
                if (ship == null) {
                    return new ResponseEntity<>(MCIdRegConstants.SHIP_NOT_FOUND, HttpStatus.NOT_FOUND);
                }
                if (ship.getIdOrganization() == org.getId().intValue()) {
                    // Generate keypair for ship
                    KeyPair shipKeyPair = CertificateUtil.generateKeyPair();
                    X509Certificate shipCert = CertificateUtil.generateCertForEntity(org.getCountry(), org.getName(), ship.getName(), ship.getName(), "", shipKeyPair.getPublic());
                    String pemCertificate = "";
                    try {
                        pemCertificate = CertificateUtil.getPemFromEncoded("CERTIFICATE", shipCert.getEncoded());
                    } catch (CertificateEncodingException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                    String pemPublicKey = CertificateUtil.getPemFromEncoded("PUBLIC KEY", shipKeyPair.getPublic().getEncoded());
                    String pemPrivateKey = CertificateUtil.getPemFromEncoded("PRIVATE KEY", shipKeyPair.getPrivate().getEncoded());
                    Certificate newMCCert = new Certificate();
                    newMCCert.setCertificate(pemCertificate);
                    newMCCert.setStart(shipCert.getNotBefore());
                    newMCCert.setEnd(shipCert.getNotAfter());
                    newMCCert.setShip(ship);
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

    
}
