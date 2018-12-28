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
package ltistarter.oauth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import ltistarter.model.IssConfigurationEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth.common.signature.SharedConsumerSecretImpl;
import org.springframework.security.oauth.consumer.BaseProtectedResourceDetails;
import org.springframework.security.oauth.consumer.client.OAuthRestTemplate;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Map;
import java.util.Base64;

/**
 * OAuth handling utils
 */
public class OAuthUtils {

    final static Logger log = LoggerFactory.getLogger(OAuthUtils.class);

    //This is added to deal with the PCKS#1 key that IMS is providing in their test platform.
    //static { Security.addProvider(new BouncyCastleProvider()); }

    public static ResponseEntity sendOAuth1Request(String url, String consumerKey, String sharedSecret, Map<String, String> params, Map<String, String> headers) {
        assert url != null;
        assert consumerKey != null;
        assert sharedSecret != null;
        BaseProtectedResourceDetails prd = new BaseProtectedResourceDetails();
        prd.setId("oauth");
        prd.setConsumerKey(consumerKey);
        prd.setSharedSecret(new SharedConsumerSecretImpl(sharedSecret));
        prd.setAdditionalParameters(params);
        prd.setAdditionalRequestHeaders(headers);
        OAuthRestTemplate restTemplate = new OAuthRestTemplate(prd);
        ResponseEntity<String> response = restTemplate.postForEntity(url, params, String.class, (Map<String, ?>) null);
        return response;
    }

    public static ResponseEntity sendOAuth2Request(String url, String clientId, String clientSecret, String accessTokenURI, Map<String, String> params) {
        assert url != null;
        assert clientId != null;
        assert clientSecret != null;
        AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider();
        BaseOAuth2ProtectedResourceDetails resource = new BaseOAuth2ProtectedResourceDetails();
        resource.setClientAuthenticationScheme(AuthenticationScheme.form);
        resource.setClientId(clientId);
        resource.setClientSecret(clientSecret);
        resource.setAccessTokenUri(accessTokenURI);
        resource.setGrantType("access");
        OAuth2AccessToken accessToken = provider.obtainAccessToken(resource, new DefaultAccessTokenRequest());
        OAuth2RestTemplate restTemplate = new OAuth2RestTemplate(resource, new DefaultOAuth2ClientContext(accessToken));
        ResponseEntity<String> response = restTemplate.postForEntity(url, params, String.class, (Map<String, ?>) null);
        return response;
    }

    public static PrivateKey loadPrivateKey(String key) throws GeneralSecurityException {
        String privateKeyContent = key.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);
        return privKey;
    }

    public static RSAPublicKey loadPublicKey(String key) throws GeneralSecurityException {
        String publicKeyContent = key.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");;
        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
        RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);
        return pubKey;
    }


}
