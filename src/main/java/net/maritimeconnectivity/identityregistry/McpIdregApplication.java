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
package net.maritimeconnectivity.identityregistry;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.ldap.LdapAutoConfiguration;

import java.security.Security;


@SpringBootApplication(exclude = LdapAutoConfiguration.class)
public class McpIdregApplication {

    public static void main(String[] args) {
        // Set awt to be headless to avoid issues when scaling images (logos)
        System.setProperty("java.awt.headless", "true");
        // Set Bouncy Castle as Provider, used for Certificates.
        Security.addProvider(new BouncyCastleProvider());
        // Allow encoded "/" (%2F) in urls. Needed for OCSP encoded GET requests.
        System.setProperty("org.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH", "true");
        SpringApplication.run(McpIdregApplication.class, args);
    }
}
