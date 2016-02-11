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
package net.maritimecloud.identityregistry.security;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.ArrayList;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.ldap.userdetails.InetOrgPerson;

public class X509UserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String certDN) throws UsernameNotFoundException {
        SimpleGrantedAuthority role = new SimpleGrantedAuthority("ROLE_USER");
        Collection<GrantedAuthority> roles = new ArrayList<GrantedAuthority>();
        roles.add(role);
        X500Name x500name = new X500Name(certDN);
        //User user = new User(getElement(x500name, BCStyle.CN), "", true /*enabled*/, true /* not-expired */, true /* cred-not-expired*/, true /* not-locked*/, roles);
        //InetOrgPerson person = new InetOrgPerson();
        InetOrgPerson.Essence essence = new InetOrgPerson.Essence();
        String name = getElement(x500name, BCStyle.CN);
        essence.setUsername(name);
        essence.setUid(name);
        essence.setDn(certDN);
        essence.setCn(new String[]{name});
        essence.setSn(name);
        essence.setO(getElement(x500name, BCStyle.O));
        essence.setOu(getElement(x500name, BCStyle.OU));
        essence.setAuthorities(roles);
        essence.setDescription(certDN);
        return essence.createUserDetails();
    }

    /**
     * Extract a value from the DN extracted from a certificate
     * 
     * @param x500name
     * @param style
     * @return
     */
    private String getElement(X500Name x500name, ASN1ObjectIdentifier style) {
        RDN cn = x500name.getRDNs(style)[0];
        return IETFUtils.valueToString(cn.getFirst().getValue());
    }
}
