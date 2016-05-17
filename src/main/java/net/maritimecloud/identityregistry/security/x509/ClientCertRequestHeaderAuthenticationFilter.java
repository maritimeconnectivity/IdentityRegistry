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

import org.springframework.security.web.authentication.preauth.PreAuthenticatedCredentialsNotFoundException;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;

/**
 * Simple extended version of RequestHeaderAuthenticationFilter. Instead of throwing an
 * Exception when the expected header is not found, just return null.
 */
public class ClientCertRequestHeaderAuthenticationFilter extends RequestHeaderAuthenticationFilter {

    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        try {
            return super.getPreAuthenticatedPrincipal(request);
        }
        catch(PreAuthenticatedCredentialsNotFoundException e) {
            return null;
        }
    }
}