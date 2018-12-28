/**
 * Copyright 2014 Unicon (R)
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ltistarter.model;

import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "iss_configuration")
public class IssConfigurationEntity extends BaseEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", nullable = false, insertable = true, updatable = true)
    private long id;
    @Basic
    @Column(name = "iss", nullable = false, insertable = true, updatable = true)
    private String iss;  //The value we receive in the issuer from the platform. We will use it to know where this come from.
    @Basic
    @Column(name = "client_id", nullable = false, insertable = true, updatable = true)
    private String clientId;  //A tool MUST thus allow multiple deployments on a given platform to share the same client_id
    @Basic
    @Column(name = "oidc_endpoint", nullable = false, insertable = true, updatable = true)
    private String oidcEndpoint;  // Where in the platform we need to ask for the oidc authentication.
    @Basic
    @Column(name = "iss_public_key", nullable = false, insertable = true, updatable = true, length = 4096)
    private String issPublicKey; //Public key of the Platform
    @Basic
    @Column(name = "uses_tool_key", nullable = false, insertable = true, updatable = true)
    private boolean usesToolKey; // if we will use a specific tool key for this platform or the default ones
    @Basic
    @Column(name = "toolKid", nullable = true, insertable = true, updatable = true)
    private String toolKid; // The tool key if number.
    @Basic
    @Column(name = "toolPublicKey", nullable = true, insertable = true, updatable = true, length = 4096)
    private String toolPublicKey;  // The tool public key
    @Basic
    @Column(name = "toolPrivateKey", nullable = true, insertable = true, updatable = true, length = 4096)
    private String toolPrivateKey;  //The tool private key


    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getOidcEndpoint() {
        return oidcEndpoint;
    }

    public void setOidcEndpoint(String oidcEndpoint) {
        this.oidcEndpoint = oidcEndpoint;
    }

    public String getIssPublicKey() {
        return issPublicKey;
    }

    public void setIssPublicKey(String issPublicKey) {
        this.issPublicKey = issPublicKey;
    }

    public boolean isUsesToolKey() {
        return usesToolKey;
    }

    public void setUsesToolKey(boolean usesToolKey) {
        this.usesToolKey = usesToolKey;
    }

    public String getToolKid() {
        return toolKid;
    }

    public void setToolKid(String toolKid) {
        this.toolKid = toolKid;
    }

    public String getToolPublicKey() {
        return toolPublicKey;
    }

    public void setToolPublicKey(String toolPublicKey) {
        this.toolPublicKey = toolPublicKey;
    }

    public String getToolPrivateKey() {
        return toolPrivateKey;
    }

    public void setToolPrivateKey(String toolPrivateKey) {
        this.toolPrivateKey = toolPrivateKey;
    }

    @Override
    public int hashCode() {
        int result = (int) id;
        result = 31 * result + (iss != null ? iss.hashCode() : 0);
        result = 31 * result + (clientId != null ? clientId.hashCode() : 0);
        result = 31 * result + (oidcEndpoint != null ? oidcEndpoint.hashCode() : 0);
        result = 31 * result + (issPublicKey != null ? issPublicKey.hashCode() : 0);
        result = 31 * result + (toolKid != null ? toolKid.hashCode() : 0);
        result = 31 * result + (toolPublicKey != null ? toolPublicKey.hashCode() : 0);
        result = 31 * result + (toolPrivateKey != null ? toolPrivateKey.hashCode() : 0);
        return result;
    }
}
