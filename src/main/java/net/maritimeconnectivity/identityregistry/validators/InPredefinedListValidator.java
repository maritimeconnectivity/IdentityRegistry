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

import org.hibernate.validator.internal.engine.messageinterpolation.util.InterpolationHelper;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.util.ArrayList;
import java.util.List;

public class InPredefinedListValidator implements ConstraintValidator<InPredefinedList, String> {

    private List<String> valueList;

    @Override
    public void initialize(InPredefinedList constraintAnnotation) {
        valueList = new ArrayList<>();
        for(String val : constraintAnnotation.acceptedValues()) {
            valueList.add(val.toLowerCase());
        }
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value != null && !valueList.contains(value.toLowerCase())) {
            String message = "The value '" + value + "' is not in the predefined list of accepted values!";
            String escaped = InterpolationHelper.escapeMessageParameter(message);
            context.disableDefaultConstraintViolation();
            context
                    .buildConstraintViolationWithTemplate(escaped)
                    .addConstraintViolation();
            return false;
        }
        return true;
    }

}
