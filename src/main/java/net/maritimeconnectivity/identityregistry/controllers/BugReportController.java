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

package net.maritimeconnectivity.identityregistry.controllers;

import io.swagger.v3.oas.annotations.Operation;
import net.maritimeconnectivity.identityregistry.exception.McpBasicRestException;
import net.maritimeconnectivity.identityregistry.model.data.BugReport;
import net.maritimeconnectivity.identityregistry.utils.EmailUtil;
import net.maritimeconnectivity.identityregistry.utils.MCPIdRegConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping(value = {"oidc", "x509"})
public class BugReportController {

    private EmailUtil emailUtil;

    @Operation(hidden = true, summary = "Reports a bug")
    @PostMapping(
            value = "/api/report-bug",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @ResponseBody
    public ResponseEntity<?> reportBug(HttpServletRequest request, @RequestBody BugReport report) throws McpBasicRestException {
        try {
            emailUtil.sendBugReport(report);
        } catch (MessagingException e) {
            throw new McpBasicRestException(HttpStatus.INTERNAL_SERVER_ERROR, MCPIdRegConstants.BUG_REPORT_CREATION_FAILED, request.getServletPath());
        }
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @Autowired
    public void setEmailUtil(EmailUtil emailUtil) {
        this.emailUtil = emailUtil;
    }
}
