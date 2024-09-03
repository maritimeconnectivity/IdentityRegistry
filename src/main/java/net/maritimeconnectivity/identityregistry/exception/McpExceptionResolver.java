/*
 * Copyright 2017 Danish Maritime Authority.
 * Copyright 2020 Maritime Connectivity Platform Consortium
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
package net.maritimeconnectivity.identityregistry.exception;

import net.maritimeconnectivity.identityregistry.model.data.ExceptionModel;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class McpExceptionResolver {

    @ExceptionHandler(McpBasicRestException.class)
    public ResponseEntity<ExceptionModel> processRestError(McpBasicRestException ex) {
        // mimics the standard spring error structure on exceptions 
        ExceptionModel exp = new ExceptionModel(ex.getTimestamp(), ex.getStatus().value(), ex.getError(), ex.getErrorMessage(), ex.path);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setContentType(MediaType.APPLICATION_JSON);
        return new ResponseEntity<>(exp, httpHeaders, ex.getStatus());
    }
}
