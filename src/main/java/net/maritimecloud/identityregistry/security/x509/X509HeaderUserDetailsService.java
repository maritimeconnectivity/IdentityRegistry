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

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.security.cert.X509Certificate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.maritimecloud.identityregistry.utils.CertificateUtil;

public class X509HeaderUserDetailsService implements UserDetailsService {

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
        UserDetails user = certUtil.getUserFromCert(userCertificate);
        if (user == null) {
            logger.error("Extraction of data from the certificate failed");
            throw new UsernameNotFoundException("Extraction of data from the certificate failed");
        }
        return user;
    }

    public void setCertUtil(CertificateUtil certUtil) {
        this.certUtil = certUtil;
    }
    
}
