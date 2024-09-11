/*
 * Copyright 2024 Maritime Connectivity Platform Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.maritimeconnectivity.identityregistry.model.data;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import net.maritimeconnectivity.identityregistry.model.JsonSerializable;
import net.maritimeconnectivity.identityregistry.validators.MCPMRN;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Schema(description = "Model object containing the patch content for migrating a Service entity")
public class ServicePatch implements JsonSerializable {
    /**
     * The new MRN of the Service
     */
    @MCPMRN
    @Schema(description = "The new MCP MRN that you want to give the service", requiredMode = Schema.RequiredMode.REQUIRED)
    private String mrn;
}
