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

package net.maritimeconnectivity.identityregistry.exception;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.http.HttpStatus;

import java.util.Date;
@Getter
@Setter
@ToString
public class McBasicRestException extends Exception {

    // mimics the standard spring error structure on exceptions 
    protected HttpStatus status;
    protected String error;
    protected String errorMessage;
    protected String path;
    protected long timestamp;
    
    public McBasicRestException(HttpStatus status, String errorMessage, String path) {
        this.status = status;
        this.errorMessage = errorMessage;
        this.path = path;
        this.timestamp = new Date().getTime();
        this.error = status.getReasonPhrase();
    }


}
