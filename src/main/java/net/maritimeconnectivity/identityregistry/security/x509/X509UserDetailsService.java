/*
 * Copyright 2017 Danish Maritime Authority.
 * Copyright 2020 Maritime Connectivity Platform Consortium
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
package net.maritimeconnectivity.identityregistry.security.x509;

import lombok.extern.slf4j.Slf4j;
import net.maritimeconnectivity.pki.CertificateHandler;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.ldap.userdetails.InetOrgPerson;

import java.util.ArrayList;
import java.util.Collection;

@Slf4j
public class X509UserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String certDN) {
        log.debug("certDN: {}", certDN);
        SimpleGrantedAuthority role = new SimpleGrantedAuthority("ROLE_USER");
        Collection<GrantedAuthority> roles = new ArrayList<>();
        roles.add(role);
        X500Name x500name = new X500Name(certDN);
        InetOrgPerson.Essence essence = new InetOrgPerson.Essence();
        String name = CertificateHandler.getElement(x500name, BCStyle.CN);
        essence.setUsername(name);
        essence.setUid(name);
        essence.setDn(certDN);
        essence.setCn(new String[]{name});
        essence.setSn(name);
        essence.setO(CertificateHandler.getElement(x500name, BCStyle.O));
        essence.setOu(CertificateHandler.getElement(x500name, BCStyle.OU));
        essence.setAuthorities(roles);
        essence.setDescription(certDN);
        log.debug("Parsed certificate, name: {}", name);
        return essence.createUserDetails();
    }

}
