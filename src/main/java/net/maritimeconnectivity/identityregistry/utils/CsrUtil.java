/*
 * Copyright 2018 Danish Maritime Authority
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.maritimeconnectivity.identityregistry.utils;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import net.maritimeconnectivity.identityregistry.exception.McpBasicRestException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.http.HttpStatus;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.StringReader;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class CsrUtil {

    /**
     * Function for converting a PEM encoded CSR to an object that can be used by Java/Bouncy Castle
     *
     * @param request a HTTP request
     * @param pemCsr  a PEM encoded CSR
     * @return an object containing a PKCS#10 CSR
     * @throws McpBasicRestException is thrown if given CSR cannot be parsed
     */
    public static JcaPKCS10CertificationRequest getCsrFromPem(HttpServletRequest request, @NonNull String pemCsr) throws McpBasicRestException {
        PemReader pemReader = new PemReader(new StringReader(pemCsr));
        try {
            PemObject pemObject = pemReader.readPemObject();
            return new JcaPKCS10CertificationRequest(pemObject.getContent());
        } catch (IOException e) {
            throw new McpBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCPIdRegConstants.ERROR_HANDLING_CSR, request.getServletPath());
        }
    }
}
