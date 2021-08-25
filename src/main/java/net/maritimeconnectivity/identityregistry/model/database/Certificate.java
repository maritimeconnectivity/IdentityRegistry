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
package net.maritimeconnectivity.identityregistry.model.database;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import net.maritimeconnectivity.identityregistry.model.database.entities.Device;
import net.maritimeconnectivity.identityregistry.model.database.entities.MMS;
import net.maritimeconnectivity.identityregistry.model.database.entities.Service;
import net.maritimeconnectivity.identityregistry.model.database.entities.User;
import net.maritimeconnectivity.identityregistry.model.database.entities.Vessel;
import net.maritimeconnectivity.pki.Revocation;
import net.maritimeconnectivity.pki.RevocationInfo;
import net.maritimeconnectivity.pki.ocsp.CertStatus;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import java.math.BigInteger;
import java.security.cert.CRLReason;
import java.util.Date;

/**
 * Model object representing a certificate
 */

@Entity
@Table(name="certificates")
@Getter
@Setter
@ToString(exclude = {"vessel", "user", "device", "service", "organization", "mms"})
@NoArgsConstructor
public class Certificate extends TimestampModel {

    @Schema(description = "The certificate in PEM format")
    @Column(name = "certificate", columnDefinition = "MEDIUMTEXT", nullable = false)
    private String certificate;

    @Column(name = "start", nullable = false)
    private Date start;

    @Column(name = "end", nullable = false)
    private Date end;

    @JsonSerialize(using = ToStringSerializer.class)
    @Column(name = "serial_number", nullable = false)
    private BigInteger serialNumber;

    @Column(name = "revoked", nullable = false)
    private boolean revoked;

    @Column(name= "revoked_at")
    private Date revokedAt;

    /* Can contain values as in rfc5280:
        unspecified (0)
        keyCompromise (1)
        CACompromise (2)
        affiliationChanged (3)
        superseded (4)
        cessationOfOperation (5)
        certificateHold (6)
        removeFromCRL (8)
        privilegeWithdrawn (9)
        AACompromise (10)
       We only store the text value, in lowercase. */
    @Column(name = "revoke_reason")
    private String revokeReason;

    @JsonIgnore
    @Column(name= "certificate_authority", nullable = false)
    private String certificateAuthority;

    @JsonIgnore
    @ManyToOne
    @JoinColumn(name = "id_vessel")
    private Vessel vessel;

    @JsonIgnore
    @ManyToOne
    @JoinColumn(name = "id_user")
    private User user;

    @JsonIgnore
    @ManyToOne
    @JoinColumn(name = "id_device")
    private Device device;

    @JsonIgnore
    @ManyToOne
    @JoinColumn(name = "id_service")
    private Service service;

    @JsonIgnore
    @ManyToOne
    @JoinColumn(name = "id_mms")
    private MMS mms;

    @JsonIgnore
    @ManyToOne
    @JoinColumn(name = "id_organization")
    private Organization organization;

    public RevocationInfo toRevocationInfo() {
        RevocationInfo info;
        if (revoked) {
            info = new RevocationInfo(serialNumber, CRLReason.values()[Revocation.getCRLReasonFromString(revokeReason)], revokedAt, CertStatus.REVOKED);
        } else {
            info = new RevocationInfo(serialNumber, null, null, CertStatus.GOOD);
        }
        return info;
    }
}
