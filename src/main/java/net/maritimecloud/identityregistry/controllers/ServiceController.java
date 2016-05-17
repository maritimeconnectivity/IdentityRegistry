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

import net.maritimecloud.identityregistry.exception.McBasicRestException;
import net.maritimecloud.identityregistry.model.Certificate;
import net.maritimecloud.identityregistry.model.CertificateRevocation;
import net.maritimecloud.identityregistry.model.Organization;
import net.maritimecloud.identityregistry.model.PemCertificate;
import net.maritimecloud.identityregistry.model.Service;
import net.maritimecloud.identityregistry.services.CertificateService;
import net.maritimecloud.identityregistry.services.OrganizationService;
import net.maritimecloud.identityregistry.services.ServiceService;
import net.maritimecloud.identityregistry.utils.AccessControlUtil;
import net.maritimecloud.identityregistry.utils.CertificateUtil;
import net.maritimecloud.identityregistry.utils.MCIdRegConstants;

import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
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

@RestController
@RequestMapping(value={"oidc", "x509"})
public class ServiceController {
    private ServiceService serviceService;
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
    public void setServiceService(ServiceService organizationService) {
        this.serviceService = organizationService;
    }

    @Autowired
    private CertificateUtil certUtil;

    /**
     * Creates a new Service
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */ 
    @RequestMapping(
            value = "/api/org/{orgShortName}/service",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<Service> createService(HttpServletRequest request, @PathVariable String orgShortName, @RequestBody Service input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the service has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                input.setIdOrganization(org.getId());
                Service newService = this.serviceService.saveService(input);
                return new ResponseEntity<Service>(newService, HttpStatus.OK);
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns info about the service identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/service/{serviceId}",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<Service> getService(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long serviceId) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the service has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                Service service = this.serviceService.getServiceById(serviceId);
                if (service == null) {
                    throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.DEVICE_NOT_FOUND, request.getServletPath());
                }
                if (service.getIdOrganization().compareTo(org.getId()) == 0) {
                    return new ResponseEntity<Service>(service, HttpStatus.OK);
                }
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Updates a Service
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/service/{serviceId}",
            method = RequestMethod.PUT)
    @ResponseBody
    public ResponseEntity<?> updateService(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long serviceId, @RequestBody Service input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the service has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                Service service = this.serviceService.getServiceById(serviceId);
                if (service == null) {
                    throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.VESSEL_NOT_FOUND, request.getServletPath());
                }
                if (service.getId().compareTo(input.getId()) == 0 && service.getIdOrganization().compareTo(org.getId()) == 0) {
                    input.selectiveCopyTo(service);
                    this.serviceService.saveService(service);
                    return new ResponseEntity<>(HttpStatus.OK);
                }
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Deletes a Service
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/service/{serviceId}",
            method = RequestMethod.DELETE)
    @ResponseBody
    public ResponseEntity<?> deleteService(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long serviceId) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the service has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                Service service = this.serviceService.getServiceById(serviceId);
                if (service == null) {
                    throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.VESSEL_NOT_FOUND, request.getServletPath());
                }
                if (service.getIdOrganization().compareTo(org.getId()) == 0) {
                    this.serviceService.deleteService(serviceId);
                    return new ResponseEntity<>(HttpStatus.OK);
                }
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns a list of services owned by the organization identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/services",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<List<Service>> getOrganizationServices(HttpServletRequest request, @PathVariable String orgShortName) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the service has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                List<Service> services = this.serviceService.listOrgServices(org.getId());
                return new ResponseEntity<List<Service>>(services, HttpStatus.OK);
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Returns new certificate for the service identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/service/{serviceId}/generatecertificate",
            method = RequestMethod.GET,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<PemCertificate> newOrgCert(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long serviceId) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the service has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                Service service = this.serviceService.getServiceById(serviceId);
                if (service == null) {
                    throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.DEVICE_NOT_FOUND, request.getServletPath());
                }
                if (service.getIdOrganization().compareTo(org.getId()) == 0) {
                    // Create the certificate and save it so that it gets an id that can be used as certificate serialnumber
                    Certificate newMCCert = new Certificate();
                    newMCCert.setService(service);
                    newMCCert = this.certificateService.saveCertificate(newMCCert);
                    // Generate keypair for service
                    KeyPair serviceKeyPair = CertificateUtil.generateKeyPair();
                    // Find special MC attributes to put in the certificate
                    HashMap<String, String> attrs = new HashMap<String, String>();
                    if (service.getMrn() != null) {
                        attrs.put(CertificateUtil.MC_OID_MRN, service.getMrn());
                    }
                    if (service.getPermissions() != null) {
                        attrs.put(CertificateUtil.MC_OID_PERMISSIONS, service.getPermissions());
                    }
                    String o = org.getShortName() + ";" + org.getName();
                    X509Certificate serviceCert = certUtil.generateCertForEntity(newMCCert.getId(), org.getCountry(), o, "service", service.getName(), "", serviceKeyPair.getPublic(), attrs);
                    String pemCertificate = "";
                    try {
                        pemCertificate = CertificateUtil.getPemFromEncoded("CERTIFICATE", serviceCert.getEncoded()).replace("\n", "\\n");
                    } catch (CertificateEncodingException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                    String pemPublicKey = CertificateUtil.getPemFromEncoded("PUBLIC KEY", serviceKeyPair.getPublic().getEncoded()).replace("\n", "\\n");
                    String pemPrivateKey = CertificateUtil.getPemFromEncoded("PRIVATE KEY", serviceKeyPair.getPrivate().getEncoded()).replace("\n", "\\n");
                    PemCertificate ret = new PemCertificate(pemPrivateKey, pemPublicKey, pemCertificate);
                    newMCCert.setCertificate(pemCertificate);
                    // The dates we extract from the cert is in localtime, so they are converted to UTC before saving into the DB
                    Calendar cal = Calendar.getInstance();
                    long offset = cal.get(Calendar.ZONE_OFFSET) + cal.get(Calendar.DST_OFFSET);
                    newMCCert.setStart(new Date(serviceCert.getNotBefore().getTime() - offset));
                    newMCCert.setEnd(new Date(serviceCert.getNotAfter().getTime() - offset));
                    newMCCert.setService(service);
                    this.certificateService.saveCertificate(newMCCert);
                    return new ResponseEntity<PemCertificate>(ret, HttpStatus.OK);
                }
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }

    /**
     * Revokes certificate for the service identified by the given ID
     * 
     * @return a reply...
     * @throws McBasicRestException 
     */
    @RequestMapping(
            value = "/api/org/{orgShortName}/service/{serviceId}/certificates/{certId}/revoke",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    public ResponseEntity<?> revokeVesselCert(HttpServletRequest request, @PathVariable String orgShortName, @PathVariable Long serviceId, @PathVariable Long certId,  @RequestBody CertificateRevocation input) throws McBasicRestException {
        Organization org = this.organizationService.getOrganizationByShortName(orgShortName);
        if (org != null) {
            // Check that the service has the needed rights
            if (AccessControlUtil.hasAccessToOrg(orgShortName)) {
                Service service = this.serviceService.getServiceById(serviceId);
                if (service == null) {
                    throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.DEVICE_NOT_FOUND, request.getServletPath());
                }
                if (service.getIdOrganization().compareTo(org.getId()) == 0) {
                    Certificate cert = this.certificateService.getCertificateById(certId);
                    Service certService = cert.getService();
                    if (certService != null && certService.getId().compareTo(service.getId()) == 0) {
                        if (!input.validateReason()) {
                            throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.INVALID_REVOCATION_REASON, request.getServletPath());
                        }
                        if (input.getRevokedAt() == null) {
                            throw new McBasicRestException(HttpStatus.BAD_REQUEST, MCIdRegConstants.INVALID_REVOCATION_DATE, request.getServletPath());
                        }
                        cert.setRevokedAt(input.getRevokedAt());
                        cert.setRevokeReason(input.getRevokationReason());
                        cert.setRevoked(true);
                        this.certificateService.saveCertificate(cert);
                        return new ResponseEntity<>(HttpStatus.OK);
                    }
                }
            }
            throw new McBasicRestException(HttpStatus.FORBIDDEN, MCIdRegConstants.MISSING_RIGHTS, request.getServletPath());
        } else {
            throw new McBasicRestException(HttpStatus.NOT_FOUND, MCIdRegConstants.ORG_NOT_FOUND, request.getServletPath());
        }
    }


}

