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
package net.maritimeconnectivity.identityregistry.utils;

import net.maritimeconnectivity.pki.PKIConstants;
import net.maritimeconnectivity.pki.pkcs11.P11PKIConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

@Component
public class PasswordUtil {

    @Autowired
    private CertificateUtil certificateUtil;

    private SecureRandom secureRandom;

    @PostConstruct
    public void setup() throws NoSuchAlgorithmException {
        if (certificateUtil.isUsingPKCS11()
                && certificateUtil.getPkiConfiguration() instanceof P11PKIConfiguration) {
            secureRandom = SecureRandom.getInstance(PKIConstants.PKCS11,
                    ((P11PKIConfiguration) certificateUtil.getPkiConfiguration()).getProvider());
        } else {
            secureRandom = new SecureRandom();
        }
    }

    public String generatePassword() {
        return new BigInteger(130, secureRandom).toString(32);
    }

}
