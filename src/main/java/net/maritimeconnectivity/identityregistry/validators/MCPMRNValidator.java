/*
 * Copyright 2020 Maritime Connectivity Platform Consortium.
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


import net.maritimeconnectivity.identityregistry.utils.MrnUtil;
import org.springframework.beans.factory.annotation.Autowired;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class MCPMRNValidator implements ConstraintValidator<MCPMRN, String> {

    private MrnUtil mrnUtil;

    @Autowired
    public void setMrnUtil(MrnUtil mrnUtil) {
        this.mrnUtil = mrnUtil;
    }

    @Override
    public void initialize(MCPMRN constraintAnnotation) {
        // This should only be relevant in unit tests where bean injection sometimes doesn't work
        if (mrnUtil == null) {
            mrnUtil = new MrnUtil();
            mrnUtil.setIpId("idp1");
        }
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        try {
            return mrnUtil.validateMCPMrn(value);
        } catch (IllegalArgumentException e) {
            context.disableDefaultConstraintViolation();
            context
                    .buildConstraintViolationWithTemplate(e.getMessage())
                    .addConstraintViolation();
            return false;
        }
    }

}
