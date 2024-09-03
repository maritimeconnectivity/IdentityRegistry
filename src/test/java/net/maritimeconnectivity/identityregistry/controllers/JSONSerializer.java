/*
 * Copyright 2018 Danish Maritime Authority
 * Copyright 2020 Maritime Connectivity Platform Consortium
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

package net.maritimeconnectivity.identityregistry.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

class JSONSerializer {

    /**
     * Helper function to serialize an object to json
     *
     * @param object
     * @return
     */
    static String serialize(Object object) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            // Convert object to JSON string
            String jsonInString = mapper.writeValueAsString(object);
            //System.out.println(jsonInString);

            // Convert object to JSON string and pretty print
            jsonInString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(object);
            //System.out.println(jsonInString);

            return jsonInString;
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }
}
