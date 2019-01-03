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
package ltistarter.lti;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.SigningKeyResolverAdapter;

import ltistarter.model.IssConfigurationEntity;
import ltistarter.model.RSAKeyEntity;
import ltistarter.model.RSAKeyId;
import ltistarter.oauth.OAuthUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PublicKey;
import java.util.Optional;

/**
 * This manages all the data processing for the LTIRequest (and for LTI in general)
 * Necessary to get appropriate TX handling and service management
 */
@Component
public class LTIJWTService {

    final static Logger log = LoggerFactory.getLogger(LTIJWTService.class);

    @Autowired
    LTIDataService ltiDataService;

    /**
     * This will check that the state has been signed by us and retrieve the issuer private key.
     * We could add here other checks if we want (like the expiration of the state, nonce used only once, etc...)
     * @param state
     * @return
     */
    //TODO: Add other checks like expiration of the state.
    public Jws<Claims> validateState(String state) throws SignatureException {
        return Jwts.parser().setSigningKeyResolver(new SigningKeyResolverAdapter() {
                // This is done because each state is signed with a different key based on the issuer... so
                // we don't know the key and we need to check it pre-extracting the claims and finding the kid
                @Override
                public Key resolveSigningKey(JwsHeader header, Claims claims) {
                PublicKey toolPublicKey;
                try {
                    // We are dealing with RS256 encryption, so we have some Oauth utils to manage the keys and
                    // convert them to keys from the string stored in DB. There are for sure other ways to manage this.
                    RSAKeyId rsaKeyId = new RSAKeyId("OWNKEY", true);
                    Optional<RSAKeyEntity> rsaKeyEntity =  ltiDataService.getRepos().rsaKeys.findById(rsaKeyId);
                    String toolPublicKeyString = rsaKeyEntity.get().getKeyKey();
                    toolPublicKey = OAuthUtils.loadPublicKey(toolPublicKeyString);
                } catch (GeneralSecurityException ex){
                    log.error("Error generating the tool public key",ex);
                    //TODO something better here.
                    return null;
                }
                return toolPublicKey;
            }
        }).parseClaimsJws(state);
        // If we are on this point, then the state signature has been validated. We can start other tasks now.
        // TODO: Here is the point to check other things in the state if we want it.

    }


    /**
     * We will just check that it is a valid signed JWT from the issuer. The logic later will decide if we
     * want to do what is asking or not. I'm not checking permissions here, that will happen later.
     * We could do other checks here, like comparing some values with the state
     * that just make us sure about the JWT being valid...
     * @param jwt
     * @return
     */
    public Jws<Claims> validateJWT(String jwt) {
        try {
            return Jwts.parser().setSigningKeyResolver(new SigningKeyResolverAdapter() {

                // This is done because each state is signed with a different key based on the issuer... so
                // we don't know the key and we need to check it pre-extracting the claims and finding the kid
                @Override
                public Key resolveSigningKey(JwsHeader header, Claims claims) {
                    try {
                        // We are dealing with RS256 encryption, so we have some Oauth utils to manage the keys and
                        // convert them to keys from the string stored in DB. There are for sure other ways to manage this.
                        IssConfigurationEntity issConfigurationEntity = ltiDataService.getRepos().issConfigurationRepository.findByPlatformKid(header.getKeyId()).get(0);

                        if (issConfigurationEntity.getJwksEndpoint() != null) {
                            try {
                                JwkProvider provider = new UrlJwkProvider(issConfigurationEntity.getJwksEndpoint());
                                Jwk jwk = provider.get(issConfigurationEntity.getPlatformKid());
                                return jwk.getPublicKey();
                            } catch (JwkException ex) {
                                log.error("Error getting the iss public key", ex);
                                //TODO something better here.
                                return null;
                            }
                        } else { //TODO If not service, then try to read the key from DB
                            return OAuthUtils.loadPublicKey(ltiDataService.getRepos().rsaKeys.findById(new RSAKeyId(issConfigurationEntity.getPlatformKid(), false)).get().getKeyKey());
                        }
                    } catch (GeneralSecurityException ex){
                        log.error("Error generating the tool public key",ex);
                        //TODO something better here.
                        return null;
                    }
                }
            }).parseClaimsJws(jwt);
        } catch (SignatureException e) {
            log.info("Invalid JWT signature: " + e.getMessage());
            log.debug("Exception " + e.getMessage(), e);
            return null;
        }
    }

}
