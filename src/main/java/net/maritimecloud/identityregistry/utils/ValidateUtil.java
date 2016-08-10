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
package net.maritimecloud.identityregistry.utils;

import net.maritimecloud.identityregistry.exception.McBasicRestException;
import org.springframework.http.HttpStatus;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;

import javax.servlet.http.HttpServletRequest;

public class ValidateUtil {

    public static void hasErrors(BindingResult bindingResult, HttpServletRequest request) throws McBasicRestException{
        if (bindingResult.hasErrors()) {
            String combinedErrMsg = "";
            for (ObjectError err : bindingResult.getAllErrors()) {
                if (combinedErrMsg.length() != 0) {
                    combinedErrMsg += ", ";
                }
                combinedErrMsg += err.getDefaultMessage();
            }
            throw new McBasicRestException(HttpStatus.BAD_REQUEST, combinedErrMsg, request.getServletPath());
        }
    }
}
