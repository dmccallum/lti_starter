package ltistarter.lti;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import ltistarter.BaseApplicationTest;
import ltistarter.model.IssConfigurationEntity;
import ltistarter.model.RSAKeyEntity;
import ltistarter.model.RSAKeyId;
import ltistarter.oauth.OAuthUtils;
import ltistarter.repository.IssConfigurationRepository;
import ltistarter.repository.RSAKeyRepository;
import org.apache.commons.lang3.time.DateUtils;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.junit4.SpringRunner;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PublicKey;
import java.util.Date;

@SuppressWarnings({"UnusedAssignment", "SpringJavaAutowiredMembersInspection", "SpringJavaAutowiringInspection"})
@RunWith(SpringRunner.class)
public class LTIJWTServiceTest extends BaseApplicationTest {

    @Autowired
    LTIJWTService ltijwtService;

    @Autowired
    RSAKeyRepository rsaKeyRepository;

    @Autowired
    IssConfigurationRepository issConfigurationRepository;

    @Value("${oicd.privatekey}")
    private String ownPrivateKey;
    @Value("${oicd.publickey}")
    private String ownPublicKey;

    private String state;

    private String iss2PublicKey = "-----BEGIN PUBLIC KEY-----" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwuvy1UpBbEzUF0C56CoA" +
            "m14BuBpUJGrJTTpSLbi4rS0xnUgAohkri9CRexbjpPNjbAYaSi4/171T2eHlfAi4" +
            "Qsv33jEdWgL8HfqFLqN09rHpxhBqWA8sFTARWgA1k7Ti/VeGclx41asCNxUnv0W+" +
            "mDeyOBSiox6cyx04LZlxs0MkmGBP1Xf4Saq8wGaBI/lUwY52aGtveMkvH/xN8DNQ" +
            "dk7Li9Q0tj3MCtpI7LE2c2h95Zl/DndDNrRAdHYgOdZg9EQcfiuWdRtUxufkdMoZ" +
            "mVoYDo7H96tulDMudC0JB0MvaOnnb+MU9jIVuvQkvrZ0jhGmTx8K0gvz2QAgWw6/" +
            "mwIDAQAB" +
            "-----END PUBLIC KEY-----";

    public String getOwnPrivateKey() {
        return ownPrivateKey;
    }

    public void setOwnPrivateKey(String ownPrivateKey) {
        this.ownPrivateKey = ownPrivateKey;
    }

    public String getOwnPublicKey() {
        return ownPublicKey;
    }

    public void setOwnPublicKey(String ownPublicKey) {
        this.ownPublicKey = ownPublicKey;
    }

    @Before
    public void setUp() throws Exception {
        assertNotNull(ltijwtService);
        rsaKeyRepository.saveAndFlush(new RSAKeyEntity("OWNKEY", true,
                getOwnPublicKey(),
                getOwnPrivateKey()));


        IssConfigurationEntity iss2 = new IssConfigurationEntity();
        iss2.setClientId("Ddbo123456");
        iss2.setIss("https://sakai.org");

        iss2.setOidcEndpoint("https://lti-ri.imsglobal.org/platforms/89/authorizations/new");
        iss2.setDeploymentId("0002");
        iss2.setToolKid("9237492835");
        iss2.setPlatformKid("9237492835");
        String tool2PrivateString = "-----BEGIN PRIVATE KEY-----" +
                "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC2QJCkV2gFoQD2" +
                "z7dQRq7g5qIxPaZJJZAJ07wPxdAJiyuWbo0bMOvH//5IqmOnUdal7iNYtDKwr9Cx" +
                "6UMqI34q6b080GPypyl058vR7Z31ZNv9d4csp81DJxW9UcSkuqTWbEDRvoHUXJLt" +
                "mhO+CokQSkS2oM1mWQeV1r3T73zPUsUq/QinK8SgGamFb+TbWQOIbqCymKwnt0no" +
                "2Vg7bqfelkAWXAIMBo9WoiNDiT7v3Ns7Fu8NJ64stXSYC8zzmTWbiUkx06SbJOKz" +
                "H0HC9NqZmeOwcDyStXYt6mVJg+bOtpctuikCZIkYeJuEwWkR9LqvAdoCs1kVnq8k" +
                "F1alNd35AgMBAAECggEALBamZvs2ENaIEyzgnazbtVBVwC+3wE4z8Aymm/Iwh36B" +
                "Rtzrib5l63YEH7QIc3uav31CU70T3iZKCB/zvYfkh6EPxFxtMVA6+Srx5ZDj+28w" +
                "wLpfmu/k+e/ElI3pUihMpAqAC71YTvUuHgh96iVGTwiIYt23kqDK8vaF6XUv7j8h" +
                "D1do+4eX9oZM03dqh2cZfC1z+xdhiEQzEOSu7qcNhml6d/rpS0EkILnmBekA1adw" +
                "UuaS/FQzcbggScSGtL2WL6CFB1gl82IGhJALqRASfRGWlkmlnTQ1fzYZdLLvWKlG" +
                "MM1mWu3zmOGxNSKQwpEHlxDpSxemFAf7RkgavA5EeQKBgQDihvyG1Ba9xtW9jO80" +
                "BPCpvyCmpX0SlhlP7kYKtZHqkEKd+SOvfzN8fxi/5BNRXnMmJFN3Mkc2sYssMzTx" +
                "MABii2e6r02AwkLUBu2DX5O/qauCbVlhr1LtvMbKTw6jnJYpGkZMqnTTS/933DPD" +
                "8xa8AsckFMsXiGRs9OpFpOF+cwKBgQDN9uUVbarh3o6xx4pABNp3QDLQeqllUlsr" +
                "Z4JqX26MELE1hA5qaccaLMtSY5Pq8Qh36tQJhZFAYz3isxvEhhIkAZZKmKi9MKDK" +
                "lf+u7vYWfpNYxUPwpB9ZRM4UCcquY24/FgKucorQI0KwYqOTJX2whKDBjiurINA2" +
                "x658s5TK4wKBgAQqQThla+mfX0y166wELzyfxATsZAlUczCyC92kiwNKFb971jki" +
                "2JqAZ78XfXdwiiN4ZYR6iy6pQwrUAjQxEsC9GXIoSP+GEt59Jh7VQg0zHHEwe4U9" +
                "SQQQBYOwwm8lsOkej45XUACWlCLrDJScwp1AW9MBAt7y5g3OzwPqzS6bAoGAFoVO" +
                "mz84liX9uFa3OTTOpodwhvdCmn+c1GwnCHaS4eHZXp6n7N7QFH6dZM7al6/vWx1k" +
                "Pf5K2Z2AYM9w09ZNGX7K7jEvEjDFBCHOqVQbuG3yspwvR5rKirpJRkujy9m3blJ7" +
                "zJNdtlCEtEC03hwVWD3ITiG7iKS336WJ4LzKIj0CgYBhhcvs9rnEx0pbMPyw3eK+" +
                "v2utJ02u3MsWmynJbvjqTSwZhRfBlDA2uzOLvPUNNOWiGjExCrAe+fFkuO8l72wu" +
                "T8RzsVTPwN9uKZOlm/sHd7KtETaMXRM94mT/uisQ9QahX48tw/c4miu+Sv2xWwQ1" +
                "sNJ4OXzO/tir0uLgMp6XcA==" +
                "-----END PRIVATE KEY-----";
        String tool2PublicString ="-----BEGIN PUBLIC KEY-----" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtkCQpFdoBaEA9s+3UEau" +
                "4OaiMT2mSSWQCdO8D8XQCYsrlm6NGzDrx//+SKpjp1HWpe4jWLQysK/QselDKiN+" +
                "Kum9PNBj8qcpdOfL0e2d9WTb/XeHLKfNQycVvVHEpLqk1mxA0b6B1FyS7ZoTvgqJ" +
                "EEpEtqDNZlkHlda90+98z1LFKv0IpyvEoBmphW/k21kDiG6gspisJ7dJ6NlYO26n" +
                "3pZAFlwCDAaPVqIjQ4k+79zbOxbvDSeuLLV0mAvM85k1m4lJMdOkmyTisx9BwvTa" +
                "mZnjsHA8krV2LeplSYPmzraXLbopAmSJGHibhMFpEfS6rwHaArNZFZ6vJBdWpTXd" +
                "+QIDAQAB" +
                "-----END PUBLIC KEY-----";
        rsaKeyRepository.saveAndFlush(new RSAKeyEntity("9237492835",true, tool2PublicString,tool2PrivateString));
        rsaKeyRepository.saveAndFlush(new RSAKeyEntity("9237492835",false, iss2PublicKey,null));
        issConfigurationRepository.saveAndFlush(iss2);

        Date date = new Date();
        this.state = Jwts.builder()
                .setHeaderParam("kid","OWNKEY")  // The key id used to sign this
                .setIssuer("ltiStarter")  //This is our own identifier, to know that we are the issuer.
                .setSubject("subject") // We store here the platform issuer to check that matches with the issuer received later
                .setAudience("Think about what goes here")  //TODO think about a useful value here
                .setExpiration(DateUtils.addSeconds(date,3600)) //a java.util.Date
                .setNotBefore(date) //a java.util.Date
                .setIssuedAt(date) // for example, now
                .setId("the id") //just a nounce... we don't use it by the moment, but it could be good if we store information about the requests in DB.
                .claim("original_iss", "https://sakai.org")  //All this claims are the information received in the OIDC initiation and some other useful things.
                .claim("loginHint", "the login hint claim")
                .claim("ltiMessageHint", "the ltiMessageHint claim")
                .claim("targetLinkUri", "the targetLinkUri claim")
                .claim("controller", "/oidc/login_initiations" )  //TODO add more things if we need it later
                .signWith(SignatureAlgorithm.RS256, OAuthUtils.loadPrivateKey(getOwnPrivateKey()))  //We sign it
                .compact();


    }

    @Test
    public void validateState() throws GeneralSecurityException {

        Jws<Claims> jws = ltijwtService.validateState(this.state);
        assertEquals(jws.getBody().getIssuer(),"ltiStarter");
    }

    @Test
    public void validateJWT() {
    }
}
