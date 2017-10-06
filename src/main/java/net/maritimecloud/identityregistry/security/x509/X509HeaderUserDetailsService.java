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
package net.maritimecloud.identityregistry.security.x509;

import net.maritimecloud.identityregistry.model.database.Organization;
import net.maritimecloud.identityregistry.model.database.Role;
import net.maritimecloud.identityregistry.services.OrganizationService;
import net.maritimecloud.identityregistry.services.RoleService;
import net.maritimecloud.pki.CertificateHandler;
import net.maritimecloud.pki.PKIIdentity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service("userDetailsService")
public class X509HeaderUserDetailsService implements UserDetailsService {

    @Autowired
    private OrganizationService organizationService;
    @Autowired
    private RoleService roleService;

    /*@Autowired
    private CertificateService certificateService;
    @Autowired
    private CertificateUtil certUtil;*/

    private static final Logger logger = LoggerFactory.getLogger(X509HeaderUserDetailsService.class);

    @Override
    public UserDetails loadUserByUsername(String certificateHeader) throws UsernameNotFoundException {
        if (certificateHeader == null || certificateHeader.length() < 10) {
            logger.warn("No certificate header found");
            throw new UsernameNotFoundException("No certificate header found");
        }
        X509Certificate userCertificate = CertificateHandler.getCertFromNginxHeader(certificateHeader);
        if (userCertificate == null) {
            logger.error("Extracting certificate from header failed");
            throw new UsernameNotFoundException("Extracting certificate from header failed");
        }
        
        // Actually authenticate certificate against root cert.
        // This is actually done by the nginx reverse proxy, so do we really need to do it again?
        /*try {
            if (!CertificateHandler.verifyCertificateChain(userCertificate, certUtil.getKeystoreHandler().getTrustStore())) {
                logger.warn("Certificate could not be verified");
                throw new UsernameNotFoundException("Certificate could not be verified");
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | InvalidAlgorithmParameterException e) {
            logger.error("Unexpected error during certificate validation!", e);
            throw new UsernameNotFoundException("Certificate could not be verified due to unexpected error!", e);
        } catch (CertPathValidatorException e) {
            logger.warn("Certificate could not be verified");
            throw new UsernameNotFoundException("Certificate could not be verified");
        }*/

        // Get user details from the certificate
        PKIIdentity user = CertificateHandler.getIdentityFromCert(userCertificate);
        if (user == null) {
            logger.warn("Extraction of data from the certificate failed");
            throw new UsernameNotFoundException("Extraction of data from the client certificate failed");
        }
        // Convert the PKIIdentity to a user object Spring can read
        InetOrgPerson.Essence essence = new InetOrgPerson.Essence();
        essence.setUid(user.getMrn());
        essence.setUsername(user.getMrn());
        essence.setO(user.getO());
        essence.setOu(user.getOu());
        // Hack alert! There is no country property in this type, so we misuse PostalAddress...
        essence.setPostalAddress(user.getCountry());
        essence.setSn(user.getSn());
        essence.setCn(new String[] { user.getCn() } );
        essence.setDn(user.getDn());
        essence.setDescription(user.getDn());
        // Convert the permissions extracted from the certificate to authorities in this API
        Collection<GrantedAuthority> newRoles = new ArrayList<>();
        if (user.getPermissions() != null && !user.getPermissions().trim().isEmpty()) {
            Organization org = organizationService.getOrganizationByMrn(user.getO());
            if (org == null) {
                logger.error("The Organization is unknown!");
                throw new UsernameNotFoundException("The Organization is unknown!");
            }
            String[] permissions = user.getPermissions().split(",");
            for(String permission: permissions) {
                logger.debug("Looking up role: " + permission);
                List<Role> foundRoles = roleService.getRolesByIdOrganizationAndPermission(org.getId(), permission);
                if (foundRoles != null) {
                    for (Role foundRole : foundRoles) {
                        newRoles.add(new SimpleGrantedAuthority(foundRole.getRoleName()));
                    }
                }
            }
        }
        // Add ROLE_USER as standard for authenticated users with no other role.
        if (newRoles.isEmpty()) {
            newRoles.add(new SimpleGrantedAuthority("ROLE_USER"));
        }
        essence.setAuthorities(newRoles);
        return essence.createUserDetails();
    }
}
