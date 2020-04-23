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
package net.maritimecloud.identityregistry.utils;

import sun.security.pkcs11.SunPKCS11;
import sun.security.pkcs11.wrapper.PKCS11RuntimeException;

import java.math.BigInteger;
import java.security.AuthProvider;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class PasswordUtil {

    private PasswordUtil() {
    }

    public static String generatePassword(AuthProvider authProvider) {
        SecureRandom secRandom;
        if (authProvider instanceof SunPKCS11) {
            try {
                secRandom = SecureRandom.getInstance("PKCS11", authProvider);
            } catch (NoSuchAlgorithmException e) {
                throw new PKCS11RuntimeException(e.getMessage(), e);
            }
        } else {
            secRandom = new SecureRandom();
        }
        return new BigInteger(130, secRandom).toString(32);
    }

}
