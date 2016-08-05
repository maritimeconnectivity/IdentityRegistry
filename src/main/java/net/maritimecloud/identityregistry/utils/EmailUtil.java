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
package net.maritimecloud.identityregistry.utils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.stereotype.Component;

@Component
public class EmailUtil {
    @Value("${net.maritimecloud.idreg.email.portal-url}")
    private String portalUrl;
    @Value("${net.maritimecloud.idreg.email.project-IDP-name}")
    private String projectIDPName;
    @Value("${net.maritimecloud.idreg.email.from}")
    private String from;
    @Value("${net.maritimecloud.idreg.email.created-org-subject}")
    private String createdOrgSubject;
    @Value("${net.maritimecloud.idreg.email.created-org-text}")
    private String createdOrgText;
    @Value("${net.maritimecloud.idreg.email.created-user-subject}")
    private String createdUserSubject;
    @Value("${net.maritimecloud.idreg.email.created-user-text}")
    private String createdUserText;

    @Autowired
    private MailSender mailSender;

    public void sendOrgCreatedEmail(String sendTo, String orgName, String adminUser, String adminPassword) throws MailException {
        if (sendTo == null || sendTo.trim().isEmpty()) {
            throw new IllegalArgumentException("No email address!");
        }
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(sendTo);
        msg.setFrom(from);
        msg.setSubject(String.format(createdOrgSubject, orgName));
        msg.setText(String.format(createdOrgText, orgName, adminUser, adminPassword, portalUrl));
        this.mailSender.send(msg);
    }

    public void sendUserCreatedEmail(String sendTo, String userName, String loginName, String loginPassword) throws MailException {
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

}
