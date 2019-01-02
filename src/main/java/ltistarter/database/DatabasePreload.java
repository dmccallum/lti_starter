/**
 * Copyright 2019 Unicon (R)
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
package ltistarter.database;

import ltistarter.config.ApplicationConfig;
import ltistarter.model.IssConfigurationEntity;
import ltistarter.model.LtiKeyEntity;
import ltistarter.model.LtiUserEntity;
import ltistarter.model.ProfileEntity;
import ltistarter.repository.IssConfigurationRepository;
import ltistarter.repository.LtiKeyRepository;
import ltistarter.repository.LtiUserRepository;
import ltistarter.repository.ProfileRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

/**
 * Check if the database has initial data in it,
 * if it is empty on startup then we populate it with some initial data
 */
@Component
@Profile("!testing")
// only load this when running the application (not for unit tests which have the 'testing' profile active)
public class DatabasePreload {

    final static Logger log = LoggerFactory.getLogger(DatabasePreload.class);

    @Autowired
    ApplicationConfig applicationConfig;

    @Autowired
    @SuppressWarnings({"SpringJavaAutowiredMembersInspection", "SpringJavaAutowiringInspection"})
    LtiKeyRepository ltiKeyRepository;
    @Autowired
    @SuppressWarnings({"SpringJavaAutowiredMembersInspection", "SpringJavaAutowiringInspection"})
    LtiUserRepository ltiUserRepository;
    @Autowired
    @SuppressWarnings({"SpringJavaAutowiredMembersInspection", "SpringJavaAutowiringInspection"})
    ProfileRepository profileRepository;
    @Autowired
    @SuppressWarnings({"SpringJavaAutowiredMembersInspection", "SpringJavaAutowiringInspection"})
    IssConfigurationRepository issConfigurationRepository;

    @PostConstruct
    public void init() {
        if (ltiKeyRepository.count() > 0) {
            // done, no preloading
            log.info("INIT - no preload");
        } else {
            // preload the sample data
            log.info("INIT - preloaded keys and user");
            // create our sample key
            ltiKeyRepository.saveAndFlush(new LtiKeyEntity("key", "secret"));
            IssConfigurationEntity iss = new IssConfigurationEntity();
            iss.setClientId("03023836-90da-4d64-bb07-0af5570e0801");
            iss.setIss("http://localhost:8080");
            String issPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi03+Yj1/1MxR3YYApadD+" +
                    "XyJ7taKlRND8dyKhtMowxFYbwXXOkrKcfoGFAlwhci1uf1kUanwNsORdmRtH/Y0F8" +
                    "iUIHxtxKzb7sY3qOwxFeL36rjIKQoxTLIeovFZe5IyP0G2gaH7HKvisYWbCfbmF9M" +
                    "ZZ88FjV5TRVLB6w0/TGLm38MwCkTm2WMIGatLH50RspTA7eVxby4FDDlNZePDPnAi" +
                    "Kug1s6a0daC3ufjAqFJ8F5LA3sRb5xrodQm+a0tBIJx3B+ve7fDLZdgeOCXWfUl6A" +
                    "a9Lip/uZA3uBdnXCD7LLKbpXvRTir8MwcatXp9R5BfDVJOH/RA3C23xLcpsAwIDAQ" +
                    "AB";
            iss.setIssPublicKey(issPublicKey);
            iss.setDeploymentId("0001");

            iss.setOidcEndpoint("http://localhost:8080/imsblis/lti13/oidc_auth");
            iss.setToolKid("9237492834");
            String toolPrivateString = "MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQCd4w5vIlPza9fGk" +
                    "MPmj8Ew/kEhFgCU9A1tkTKMeK58uNR/M/OIIqFPOvan8qK/bXhcYMxdYJCZcvkmjE" +
                    "mwI8ekBUYsYm5TcYGNOvj8QXoq0NJ6RPAYH7rc5zlEv/YQg/JP48vn3VHC020Cwyv" +
                    "t+L5tWXF7dqyTWAMife9j0DyWAulLCEgJC5eUAvRzHdnUGyjc30cVzSQKDaRRXnYD" +
                    "7i0SsAol/8Jp+2grGD8h/rMkWlvq0z+QBXpN9tZ1H6/0fzjNi4zx9dNdqUOJuUqBb" +
                    "QmF4Pd/mYzLRgmPKplJ9WjhQZiT/uQeRX7M1TBtiqHkGd5XiBVllR8iceKBkG2NNB" +
                    "iHAgMBAAECggEBAIPoK6n7kwm+opI5ZgGdPnlRIlajDC9lykYs1X94X8bBoH75h0/" +
                    "IJt6L04Cy/PdTXQhIstSclZIt9SwYboPjEKre4Sa5wZSjMuosR9JwXcGhnwcZy0FM" +
                    "WRCveTAP9GMN6YaHOVbol6NegieZqXzyoR24aVAN8NZU5KGPd037rnJggknyCRxT/" +
                    "pPPhdh4Z8TRXmyyN+tYwXRmbovNOu4T5Xpa2yy9K19Vy5z7JXP9lpWMPgmfgEaNbK" +
                    "OI/Yta6/pC/3RHLeKDCwXE+e5nKPF5krWL/Eu3xCrW36Vq4vqOG+qOtkE02xvon+F" +
                    "9zznDWe1I5FkEtmfonesl/h6bBPdxbykCgYEAzSPmeoSWBybgCczMbrzq7ZHh7T8e" +
                    "dPq+bw69nNQVlGd/YCSinEJA5+d+D69Ra/SXafjWhjL+bOiYXGSxf8S/7d+ZrIWmF" +
                    "7yK5jWzMIdSTKgLHkCBLAO5cYT1DzZmQNF+DOvXD/xtUkaNXg03Kd+EqdjRapEfH9" +
                    "9koy0ryrTgwiUCgYEAxQgGLe9MsOYcZVTO4XcFuaFmaFIfdXc6gnnLzJbshVuIA8h" +
                    "GHLQcZKMoUK0oipkQnMt+4KzTkawEqypFHK3l7sXygJ40Wul2mlGjja3+WNUurhQc" +
                    "1/5f2fMcBef1mG4ykTKgPbiZZXoOMnElXV+pyw6mXJiIzY6spQ16fwwB0jsCgYEAl" +
                    "RkfvjK5nG8b7OOGPoJeudcK/1Wd/GX2nV94XxEish9bS/S0n5/j7umpDRtesXkvx9" +
                    "0NhrJvi5aujpC9FeFZojmfRu5Inv3xcorbN01TetW0ZwN5HxWB5kk9mBXw0fGxjRC" +
                    "o2jyc9GzE+PPgATYtBQnKg4sAtTi3u4XsS0OWDGUCgYEAtvF7Y11E9R/ED+ZN7RTp" +
                    "cPHGt2hBI31gC1PxgfZEiJJzWSe0yeQGVP8VaMtO0FnNDfj4xr5R93kkIJWv9DAXR" +
                    "bvwLbI3ZI5PfHv/A4chmfPfUu0D1x2ufBz50RYOeMkhFKZQGN71Nz68PePG0MsJSa" +
                    "xBlcpfg5VNAjfgnGRWsI8CgYEAmZyWUOPAhjEycFLNhBwy+6eZKTreVR8zNO6ZvGo" +
                    "MDl6HR6NURO4B4w+Zfzxi9CRfKGs6/3wgehhEP+uJBBlrfH3REwrmB0/fKO4bCfLY" +
                    "ijwTgVdqU6DBrBa3n4cUQ/noGpovKUiXDM4uLWf0oDAk/8BIpUTKb4khgNnEm8e8B" +
                    "7Y=";
            iss.setToolPrivateKey(toolPrivateString);

            String toolPublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAneMObyJT82vXxpDD5o/BM" +
                    "P5BIRYAlPQNbZEyjHiufLjUfzPziCKhTzr2p/Kiv214XGDMXWCQmXL5JoxJsCPHpA" +
                    "VGLGJuU3GBjTr4/EF6KtDSekTwGB+63Oc5RL/2EIPyT+PL591RwtNtAsMr7fi+bVl" +
                    "xe3ask1gDIn3vY9A8lgLpSwhICQuXlAL0cx3Z1Bso3N9HFc0kCg2kUV52A+4tErAK" +
                    "Jf/CaftoKxg/If6zJFpb6tM/kAV6TfbWdR+v9H84zYuM8fXTXalDiblKgW0JheD3f" +
                    "5mMy0YJjyqZSfVo4UGYk/7kHkV+zNUwbYqh5BneV4gVZZUfInHigZBtjTQYhwIDAQ" +
                    "AB";
            iss.setToolPublicKey(toolPublicKey);

            iss.setUsesToolKey(true);
            issConfigurationRepository.saveAndFlush(iss);

            IssConfigurationEntity iss2 = new IssConfigurationEntity();
            iss2.setClientId("Ddbo123456");
            iss2.setIss("https://sakai.org");
            String iss2PublicKey = "-----BEGIN PUBLIC KEY-----" +
                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwuvy1UpBbEzUF0C56CoA" +
                    "m14BuBpUJGrJTTpSLbi4rS0xnUgAohkri9CRexbjpPNjbAYaSi4/171T2eHlfAi4" +
                    "Qsv33jEdWgL8HfqFLqN09rHpxhBqWA8sFTARWgA1k7Ti/VeGclx41asCNxUnv0W+" +
                    "mDeyOBSiox6cyx04LZlxs0MkmGBP1Xf4Saq8wGaBI/lUwY52aGtveMkvH/xN8DNQ" +
                    "dk7Li9Q0tj3MCtpI7LE2c2h95Zl/DndDNrRAdHYgOdZg9EQcfiuWdRtUxufkdMoZ" +
                    "mVoYDo7H96tulDMudC0JB0MvaOnnb+MU9jIVuvQkvrZ0jhGmTx8K0gvz2QAgWw6/" +
                    "mwIDAQAB" +
                    "-----END PUBLIC KEY-----";
            iss2.setIssPublicKey(iss2PublicKey);
            iss2.setOidcEndpoint("https://lti-ri.imsglobal.org/platforms/89/authorizations/new");
            iss2.setDeploymentId("0002");
            iss2.setToolKid("9237492835");
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
            iss2.setToolPrivateKey(tool2PrivateString);
            String tool2PublicKey ="-----BEGIN PUBLIC KEY-----" +
                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtkCQpFdoBaEA9s+3UEau" +
                    "4OaiMT2mSSWQCdO8D8XQCYsrlm6NGzDrx//+SKpjp1HWpe4jWLQysK/QselDKiN+" +
                    "Kum9PNBj8qcpdOfL0e2d9WTb/XeHLKfNQycVvVHEpLqk1mxA0b6B1FyS7ZoTvgqJ" +
                    "EEpEtqDNZlkHlda90+98z1LFKv0IpyvEoBmphW/k21kDiG6gspisJ7dJ6NlYO26n" +
                    "3pZAFlwCDAaPVqIjQ4k+79zbOxbvDSeuLLV0mAvM85k1m4lJMdOkmyTisx9BwvTa" +
                    "mZnjsHA8krV2LeplSYPmzraXLbopAmSJGHibhMFpEfS6rwHaArNZFZ6vJBdWpTXd" +
                    "+QIDAQAB" +
                    "-----END PUBLIC KEY-----";
            iss2.setToolPublicKey(tool2PublicKey);
            iss2.setUsesToolKey(true);
            issConfigurationRepository.saveAndFlush(iss2);

            IssConfigurationEntity iss3 = new IssConfigurationEntity();
            iss3.setClientId("imstestuser");
            iss3.setIss("ltiadv-cert.imsglobal.org");
            String iss3PublicKey = "-----BEGIN PUBLIC KEY-----" +
                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwuvy1UpBbEzUF0C56CoA" +
                    "m14BuBpUJGrJTTpSLbi4rS0xnUgAohkri9CRexbjpPNjbAYaSi4/171T2eHlfAi4" +
                    "Qsv33jEdWgL8HfqFLqN09rHpxhBqWA8sFTARWgA1k7Ti/VeGclx41asCNxUnv0W+" +
                    "mDeyOBSiox6cyx04LZlxs0MkmGBP1Xf4Saq8wGaBI/lUwY52aGtveMkvH/xN8DNQ" +
                    "dk7Li9Q0tj3MCtpI7LE2c2h95Zl/DndDNrRAdHYgOdZg9EQcfiuWdRtUxufkdMoZ" +
                    "mVoYDo7H96tulDMudC0JB0MvaOnnb+MU9jIVuvQkvrZ0jhGmTx8K0gvz2QAgWw6/" +
                    "mwIDAQAB" +
                    "-----END PUBLIC KEY-----";
            iss3.setIssPublicKey(iss3PublicKey);
            iss3.setOidcEndpoint("https://ltiadvantagevalidator.imsglobal.org/ltitool/oidcauthentication.html");
            iss3.setDeploymentId("testdeploy");
            iss3.setToolKid("imstester_4");
            String tool3PrivateString = "-----BEGIN PRIVATE KEY-----" +
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
            iss3.setToolPrivateKey(tool3PrivateString);
            String tool3PublicKey ="-----BEGIN PUBLIC KEY-----" +
                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtkCQpFdoBaEA9s+3UEau" +
                    "4OaiMT2mSSWQCdO8D8XQCYsrlm6NGzDrx//+SKpjp1HWpe4jWLQysK/QselDKiN+" +
                    "Kum9PNBj8qcpdOfL0e2d9WTb/XeHLKfNQycVvVHEpLqk1mxA0b6B1FyS7ZoTvgqJ" +
                    "EEpEtqDNZlkHlda90+98z1LFKv0IpyvEoBmphW/k21kDiG6gspisJ7dJ6NlYO26n" +
                    "3pZAFlwCDAaPVqIjQ4k+79zbOxbvDSeuLLV0mAvM85k1m4lJMdOkmyTisx9BwvTa" +
                    "mZnjsHA8krV2LeplSYPmzraXLbopAmSJGHibhMFpEfS6rwHaArNZFZ6vJBdWpTXd" +
                    "+QIDAQAB" +
                    "-----END PUBLIC KEY-----";
            iss3.setToolPublicKey(tool3PublicKey);
            iss3.setUsesToolKey(true);
            issConfigurationRepository.saveAndFlush(iss3);




            // create our sample user
            LtiUserEntity user = ltiUserRepository.saveAndFlush(new LtiUserEntity("azeckoski", null));
            ProfileEntity profile = profileRepository.saveAndFlush(new ProfileEntity("AaronZeckoski", null, "azeckoski@test.com"));
            // now add profile to the user
            user.setProfile(profile);
            profile.getUsers().add(user);
            ltiUserRepository.saveAndFlush(user);
        }
    }

}
