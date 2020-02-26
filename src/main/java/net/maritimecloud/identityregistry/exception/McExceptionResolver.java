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
package net.maritimecloud.identityregistry.exception;

import net.maritimecloud.identityregistry.model.data.ExceptionModel;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class McExceptionResolver {

    @ExceptionHandler(McBasicRestException.class)
    public ResponseEntity<ExceptionModel> processRestError(McBasicRestException ex) {
        // mimics the standard spring error structure on exceptions 
        ExceptionModel exp = new ExceptionModel(ex.getTimestamp(), ex.getStatus().value(), ex.getError(), ex.getErrorMessage(), ex.path);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setContentType(MediaType.APPLICATION_JSON_UTF8);
        return new ResponseEntity<>(exp, httpHeaders, ex.getStatus());
    }
}
