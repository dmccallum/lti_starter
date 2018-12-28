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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import ltistarter.model.BaseEntity;
import ltistarter.model.IssConfigurationEntity;
import ltistarter.model.KeyRequestEntity;
import ltistarter.model.LtiContextEntity;
import ltistarter.model.LtiKeyEntity;
import ltistarter.model.LtiLinkEntity;
import ltistarter.model.LtiMembershipEntity;
import ltistarter.model.LtiResultEntity;
import ltistarter.model.LtiServiceEntity;
import ltistarter.model.LtiUserEntity;
import ltistarter.oauth.OAuthUtils;
import ltistarter.repository.AllRepositories;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.Query;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PublicKey;
import java.util.List;

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
    public Key validateState(String state) {
        try {
            Jws<Claims> jws= Jwts.parser().setSigningKeyResolver(new SigningKeyResolverAdapter() {

                // This is done because each state is signed with a different key based on the issuer... so
                // we don't know the key and we need to check it pre-extracting the claims and finding the kid
                @Override
                public Key resolveSigningKey(JwsHeader header, Claims claims) {
                    PublicKey toolPublicKey = null;
                    IssConfigurationEntity issConfigurationEntity = ltiDataService.getRepos().issConfigurationRepository.findByToolKid(header.getKeyId()).get(0);
                    try {
                        // We are dealing with RS256 encryption, so we have some Oauth utils to manage the keys and
                        // convert them to keys from the string stored in DB. There are for sure other ways to manage this.
                        toolPublicKey = OAuthUtils.loadPublicKey(issConfigurationEntity.getToolPublicKey());
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
            // In this case we will return the iss public key.
            PublicKey issPublicKey = null;
            try {
                IssConfigurationEntity issConfigurationEntity = ltiDataService.getRepos().issConfigurationRepository.findByToolKid(jws.getHeader().getKeyId()).get(0);
                issPublicKey = OAuthUtils.loadPublicKey(issConfigurationEntity.getIssPublicKey());
            } catch (GeneralSecurityException ex){
                log.error("Error generating the iss public key",ex);
                //TODO something better here.
                return null;
            }
            return issPublicKey;
        } catch (SignatureException e) {
            log.info("Invalid JWT signature: " + e.getMessage());
            log.debug("Exception " + e.getMessage(), e);
            return null;
        }
    }

    /**
     * We will just check that it is a valid signed JWT from the issuer. The logic later will decide if we
     * want to do what is asking or not. I'm not checking permissions here, that will happen later.
     * We could do other checks here, like expiration dates or comparing some values with the state
     * that just make us sure about the JWT being valid...
     * @param jwt
     * @param secretKey
     * @return
     */
    public Jws<Claims> validateJWT(String jwt, Key secretKey) {
        try {
            return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwt);
        } catch (SignatureException e) {
            log.info("Invalid JWT signature: " + e.getMessage());
            log.debug("Exception " + e.getMessage(), e);
            return null;
        }
    }

}
