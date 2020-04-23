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
package net.maritimeconnectivity.identityregistry.validators;

import net.maritimeconnectivity.identityregistry.model.database.entities.VesselAttribute;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

import java.util.Arrays;

@Component
public class VesselAttributeValidator implements Validator {
    @Override
    public boolean supports(Class<?> clazz) {
        return VesselAttribute.class.equals(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "attributeName", "attributeName.empty", "attributeName must not be empty");
        ValidationUtils.rejectIfEmptyOrWhitespace(errors, "attributeValue", "attributeValue.empty", "attributeValue must not be empty");
        VesselAttribute vesselAttribute = (VesselAttribute) target;
        if (vesselAttribute.getAttributeName() != null && !Arrays.asList("imo-number", "mmsi-number", "callsign", "flagstate", "ais-class", "port-of-register").contains(vesselAttribute.getAttributeName())) {
            errors.rejectValue("attributeName", "illegal.value", "attributeName value is invalid");
        }
    }
}
