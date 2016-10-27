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
package net.maritimecloud.identityregistry.security.x509;

import net.maritimecloud.identityregistry.model.database.Organization;
import net.maritimecloud.identityregistry.model.database.Role;
import net.maritimecloud.identityregistry.services.OrganizationService;
import net.maritimecloud.identityregistry.services.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.maritimecloud.identityregistry.utils.CertificateUtil;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.stereotype.Service;

@Service("userDetailsService")
public class X509HeaderUserDetailsService implements UserDetailsService {

    @Autowired
    private OrganizationService organizationService;
    @Autowired
    private RoleService roleService;
    @Autowired
    private CertificateUtil certUtil;

    private static final Logger logger = LoggerFactory.getLogger(X509HeaderUserDetailsService.class);

    @Override
    public UserDetails loadUserByUsername(String certificateHeader) throws UsernameNotFoundException {
        if (certificateHeader == null || certificateHeader.length() < 10) {
            logger.debug("No certificate header found");
            throw new UsernameNotFoundException("No certificate header found");
        }
        X509Certificate userCertificate = certUtil.getCertFromString(certificateHeader);
        if (userCertificate == null) {
            logger.error("Extracting certificate from header failed");
            throw new UsernameNotFoundException("Extracting certificate from header failed");
        }
        
        // Actually authenticate certificate against root cert.
        if (!certUtil.verifyCertificate(userCertificate)) {
            throw new UsernameNotFoundException("Not authenticated");
        }
        // Get user details from the certificate
        UserDetails user = certUtil.getUserFromCert(userCertificate);
        if (user == null) {
            logger.error("Extraction of data from the certificate failed");
            throw new UsernameNotFoundException("Extraction of data from the certificate failed");
        }
        // Convert the permissions extracted from the certificate to authorities in this API
        InetOrgPerson person = ((InetOrgPerson)user);
        String certOrg = person.getO();
        Organization org = organizationService.getOrganizationByMrn(certOrg);
        if (org == null) {
            throw new UsernameNotFoundException("Unknown Organization");
        }
        Collection<GrantedAuthority> newRoles = new ArrayList<GrantedAuthority>();
        logger.debug("Looking up roles");
        for (GrantedAuthority role : user.getAuthorities()) {
            logger.debug("Looking up roles");
            String auth = role.getAuthority();
            String[] auths = auth.split(",");
            for (String auth2 : auths) {
                logger.debug("Looking up role: " + auth2);
                List<Role> foundRoles = roleService.getRolesByIdOrganizationAndPermission(org.getId(), auth2);
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
        InetOrgPerson.Essence essence = new InetOrgPerson.Essence((InetOrgPerson) user);
        essence.setAuthorities(newRoles);
        return essence.createUserDetails();
    }
}
