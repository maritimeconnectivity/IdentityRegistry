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

package net.maritimecloud.identityregistry.controllers;

import io.swagger.annotations.ApiOperation;
import net.maritimecloud.identityregistry.exception.McBasicRestException;
import net.maritimecloud.identityregistry.model.data.BugReport;
import net.maritimecloud.identityregistry.utils.EmailUtil;
import net.maritimecloud.identityregistry.utils.MCIdRegConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping(value={"oidc", "x509"})
public class BugReportController {

    @Autowired
    private EmailUtil emailUtil;

    @ApiOperation(hidden=true, value = "Reports a bug")
    @RequestMapping(
            value = "/api/report-bug",
            method = RequestMethod.POST,
            produces = "application/json;charset=UTF-8")
    @ResponseBody
    public ResponseEntity<?> reportBug(HttpServletRequest request, @RequestBody BugReport report) throws McBasicRestException {
        try {
            emailUtil.sendBugReport(report);
        } catch (MessagingException e) {
            throw new McBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCIdRegConstants.BUG_REPORT_CREATION_FAILED, request.getServletPath());
        }
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
