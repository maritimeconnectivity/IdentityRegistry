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

package net.maritimecloud.identityregistry.utils;

import net.maritimecloud.identityregistry.exception.McBasicRestException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.StringReader;

public class CsrUtil {

    public static JcaPKCS10CertificationRequest getCsrFromPem(HttpServletRequest request, String pemCsr) throws McBasicRestException {
        PemReader pemReader = new PemReader(new StringReader(pemCsr));
        try {
            PemObject pemObject = pemReader.readPemObject();
            return new JcaPKCS10CertificationRequest(pemObject.getContent());
        } catch (IOException e) {
            throw new McBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCIdRegConstants.ERROR_HANDLING_CSR, request.getServletPath());
        }
    }
}
