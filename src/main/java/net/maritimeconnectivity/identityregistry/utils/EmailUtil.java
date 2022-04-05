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
package net.maritimeconnectivity.identityregistry.utils;

import net.maritimeconnectivity.identityregistry.model.data.BugReport;
import net.maritimeconnectivity.identityregistry.model.data.BugReportAttachment;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.mail.util.ByteArrayDataSource;
import java.util.Base64;

@Component
public class EmailUtil {
    @Value("${net.maritimeconnectivity.idreg.email.portal-url}")
    private String portalUrl;

    @Value("${net.maritimeconnectivity.idreg.email.project-IDP-name}")
    private String projectIDPName;

    @Value("${net.maritimeconnectivity.idreg.email.from}")
    private String from;

    @Value("${net.maritimeconnectivity.idreg.email.admin-email}")
    private String[] adminEmail;

    @Value("${net.maritimeconnectivity.idreg.email.org-awaiting-approval-subject}")
    private String orgAwaitingApprovalSubject;

    @Value("${net.maritimeconnectivity.idreg.email.org-awaiting-approval-text}")
    private String orgAwaitingApprovalText;

    @Value("${net.maritimeconnectivity.idreg.email.admin-org-awaiting-approval-text}")
    private String adminOrgAwaitingApprovalText;

    @Value("${net.maritimeconnectivity.idreg.email.created-user-subject}")
    private String createdUserSubject;

    @Value("${net.maritimeconnectivity.idreg.email.created-user-text}")
    private String createdUserText;

    @Value("${net.maritimeconnectivity.idreg.email.bug-report-email}")
    private String bugReportEmail;

    private JavaMailSender mailSender;

    @Autowired
    public void setMailSender(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    public void sendOrgAwaitingApprovalEmail(String sendTo, String orgName) {
        if (sendTo == null || sendTo.trim().isEmpty()) {
            throw new IllegalArgumentException("No email address!");
        }
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(sendTo);
        msg.setFrom(from);
        msg.setSubject(String.format(orgAwaitingApprovalSubject, orgName));
        msg.setText(String.format(orgAwaitingApprovalText, orgName));
        this.mailSender.send(msg);
    }

    public void sendAdminOrgAwaitingApprovalEmail(String orgName, String orgMrn) {
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(adminEmail);
        msg.setFrom(from);
        msg.setSubject(String.format(orgAwaitingApprovalSubject, orgName));
        msg.setText(String.format(adminOrgAwaitingApprovalText, orgName, orgMrn));
        this.mailSender.send(msg);
    }

    public void sendUserCreatedEmail(String sendTo, String userName, String loginName, String loginPassword) {
        if (sendTo == null || sendTo.trim().isEmpty()) {
            throw new IllegalArgumentException("No email address!");
        }
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(sendTo);
        msg.setFrom(from);
        msg.setSubject(createdUserSubject);
        msg.setText(String.format(createdUserText, userName, loginName, loginPassword, portalUrl, projectIDPName));
        this.mailSender.send(msg);
    }

    public void sendBugReport(BugReport report) throws MessagingException {
        MimeMessage message = this.mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true);
        helper.setTo(bugReportEmail);
        helper.setFrom(from);
        helper.setSubject(report.getSubject());
        helper.setText(report.getDescription());
        if (report.getAttachments() != null) {
            for (BugReportAttachment attachment : report.getAttachments()) {
                // Decode base64 encoded data
                byte[] data =  Base64.getDecoder().decode(attachment.getData());
                ByteArrayDataSource dataSource = new ByteArrayDataSource(data, attachment.getMimetype());
                helper.addAttachment(attachment.getName(), dataSource);
            }
        }
        this.mailSender.send(message);
    }

}
