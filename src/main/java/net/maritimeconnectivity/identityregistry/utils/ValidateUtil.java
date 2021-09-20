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

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import net.maritimeconnectivity.identityregistry.exception.McpBasicRestException;
import org.springframework.http.HttpStatus;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;

import javax.servlet.http.HttpServletRequest;
import java.util.StringJoiner;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class ValidateUtil {

    public static void hasErrors(BindingResult bindingResult, HttpServletRequest request) throws McpBasicRestException {
        if (bindingResult.hasErrors()) {
            StringJoiner stringJoiner = new StringJoiner(", ");
            for (ObjectError err : bindingResult.getAllErrors()) {
                stringJoiner.add(err.getDefaultMessage());
            }
            throw new McpBasicRestException(HttpStatus.BAD_REQUEST, stringJoiner.toString(), request.getServletPath());
        }
    }
}
