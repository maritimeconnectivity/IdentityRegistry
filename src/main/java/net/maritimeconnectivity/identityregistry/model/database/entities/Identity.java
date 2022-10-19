package net.maritimeconnectivity.identityregistry.model.database.entities;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import net.maritimeconnectivity.identityregistry.model.database.Certificate;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import java.util.Set;

import static io.swagger.v3.oas.annotations.media.Schema.AccessMode.READ_ONLY;

@Entity
@Table(name = "identities")
@Getter
@Setter
@ToString(exclude = "certificates")
@NoArgsConstructor
@Schema(description = "Model object representing an identity")
public class Identity extends EntityModel {

    @Schema(description = "The set of certificates of the identity. Cannot be created/updated by editing in the model. Use the dedicated create and revoke calls.", accessMode = READ_ONLY)
    @OneToMany(fetch = FetchType.EAGER, mappedBy = "identity")
    private Set<Certificate> certificates;

    @Override
    public void assignToCert(Certificate cert) {
        cert.setIdentity(this);
    }
}
