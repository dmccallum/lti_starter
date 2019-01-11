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

import org.apache.commons.lang3.StringUtils;

import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "rsa_key")
public class RSAKeyEntity extends BaseEntity {
    @EmbeddedId
    private RSAKeyId kid;
    @Basic
    @Column(name = "public_key_sha256", unique = false, nullable = true, insertable = true, updatable = true, length = 64)
    private String publicKeySha256;
    @Basic
    @Column(name = "key_key", unique = false, nullable = true, insertable = true, updatable = true, length = 4096)
    private String keyKey;
    @Basic
    @Column(name = "private_key_sha256", unique = false, nullable = true, insertable = true, updatable = true, length = 64)
    private String privateKeySha256;
    @Basic
    @Column(name = "private_key_key", unique = false, nullable = true, insertable = true, updatable = true, length = 4096)
    private String privateKeyKey;

    protected RSAKeyEntity() {
    }

    /**
     * @param kid  the key id
     * @param publicKey  the plain text public key
     * @param privateKey the plain text private key
     */
    public RSAKeyEntity(String kid, Boolean tool, String publicKey, String privateKey) {
        RSAKeyId rsaKeyId = new RSAKeyId(kid,tool);
        this.kid = rsaKeyId;
        this.keyKey = publicKey;
        if (StringUtils.isNotEmpty(publicKey)) {
            this.publicKeySha256 = makeSHA256(publicKey);
        } else {
            this.publicKeySha256 = null;
        }
        this.privateKeyKey = privateKey;
        if (StringUtils.isNotEmpty(privateKey)) {
            this.privateKeySha256 = makeSHA256(privateKey);
        } else {
            this.privateKeySha256 = null;
        }

    }

    public RSAKeyId getKid() {
        return kid;
    }

    public void setKid(RSAKeyId kid) {
        this.kid = kid;
    }

    public String getPublicKeySha256() {
        return publicKeySha256;
    }

    public void setPublicKeySha256(String publicKeySha256) {
        this.publicKeySha256 = publicKeySha256;
    }

    public String getKeyKey() {
        return keyKey;
    }

    public void setKeyKey(String keyKey) {
        this.keyKey = keyKey;
    }

    public String getPrivateKeySha256() {
        return privateKeySha256;
    }

    public void setPrivateKeySha256(String privateKeySha256) {
        this.privateKeySha256 = privateKeySha256;
    }

    public String getPrivateKeyKey() {
        return privateKeyKey;
    }

    public void setPrivateKeyKey(String privateKeyKey) {
        this.privateKeyKey = privateKeyKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        RSAKeyEntity that = (RSAKeyEntity) o;

        if (kid != that.kid) return false;
        if (keyKey != null ? !keyKey.equals(that.keyKey) : that.keyKey != null) return false;
        if (publicKeySha256 != null ? !publicKeySha256.equals(that.publicKeySha256) : that.publicKeySha256 != null) return false;
        if (privateKeyKey != null ? !privateKeyKey.equals(that.privateKeyKey) : that.privateKeyKey != null) return false;
        return privateKeySha256 != null ? privateKeySha256.equals(that.privateKeySha256) : that.privateKeySha256 == null;
    }

    @Override
    public int hashCode() {
        int result =  kid != null ? kid.hashCode() : 0;
        result = 31 * result + (publicKeySha256 != null ? publicKeySha256.hashCode() : 0);
        result = 31 * result + (privateKeySha256 != null ? privateKeySha256.hashCode() : 0);
        result = 31 * result + (keyKey != null ? keyKey.hashCode() : 0);
        result = 31 * result + (privateKeyKey != null ? privateKeyKey.hashCode() : 0);
        return result;
    }

}
