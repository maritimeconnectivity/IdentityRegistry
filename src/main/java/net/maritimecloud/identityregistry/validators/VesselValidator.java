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
package net.maritimecloud.identityregistry.validators;


import net.maritimecloud.identityregistry.model.database.entities.Vessel;
import net.maritimecloud.identityregistry.model.database.entities.VesselAttribute;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

@Component
public class VesselValidator implements Validator {
    @Autowired
    private VesselAttributeValidator vesselAttributeValidator;

    @Override
    public boolean supports(Class<?> clazz) {
        return Vessel.class.equals(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "vesselOrgId", "vesselOrgId.empty", "vesselOrgId  is required.");
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "name", "name.empty", "name is required.");
        Vessel vessel = (Vessel) target;
        if (vessel.getAttributes() != null) {
            for (int i = 0; i < vessel.getAttributes().size(); ++i) {
                try {
                    errors.pushNestedPath("attributes[" + i + "]");
                    ValidationUtils.invokeValidator(this.vesselAttributeValidator, vessel.getAttributes().get(i), errors);
                } finally {
                    errors.popNestedPath();
                }
            }
        }
    }
}
