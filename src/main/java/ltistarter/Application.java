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
package ltistarter;

import com.google.common.collect.ImmutableList;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import ltistarter.lti.LTI3OAuthProviderProcessingFilter;
import ltistarter.lti.LTIConsumerDetailsService;
import ltistarter.lti.LTIDataService;
import ltistarter.lti.LTIJWTService;
import ltistarter.lti.LTIOAuthAuthenticationHandler;
import ltistarter.lti.LTIOAuthProviderProcessingFilter;
import ltistarter.model.RSAKeyEntity;
import ltistarter.oauth.MyConsumerDetailsService;
import ltistarter.oauth.MyOAuthAuthenticationHandler;
import ltistarter.oauth.MyOAuthNonceServices;
import ltistarter.oauth.OAuthUtils;
import ltistarter.oauth.ZeroLeggedOAuthProviderProcessingFilter;
import org.apache.commons.lang3.tuple.Pair;
import org.h2.server.web.WebServlet;
import org.pac4j.core.client.Client;
import org.pac4j.core.client.Clients;
import org.pac4j.core.config.Config;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.http.callback.PathParameterCallbackUrlResolver;
import org.pac4j.core.matching.Matcher;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.profile.OidcProfile;
import org.pac4j.oidc.profile.creator.OidcProfileCreator;
import org.pac4j.oidc.profile.creator.TokenValidator;
import org.pac4j.oidc.redirect.OidcRedirectActionBuilder;
import org.pac4j.springframework.security.web.CallbackFilter;
import org.pac4j.springframework.security.web.Pac4jEntryPoint;
import org.pac4j.springframework.security.web.SecurityFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth.provider.OAuthProcessingFilterEntryPoint;
import org.springframework.security.oauth.provider.token.InMemoryProviderTokenServices;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringValueResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.annotation.PostConstruct;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@ComponentScan("ltistarter")
@Configuration
@EnableAutoConfiguration
@EnableTransactionManagement // enables TX management and @Transaction
@EnableCaching // enables caching and @Cache* tags
@EnableWebSecurity // enable spring security and web mvc hooks
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
// allows @Secured flag - proxyTargetClass = true causes this to die
public class Application implements WebMvcConfigurer {

    static final Logger log = LoggerFactory.getLogger(Application.class);

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    /**
     * Allows access to the various config values (from application.properties) using @Value
     */
    @Bean
    public static PropertySourcesPlaceholderConfigurer propertyPlaceholderConfigurer() {
        return new PropertySourcesPlaceholderConfigurer() {
            @Override
            protected void doProcessProperties(ConfigurableListableBeanFactory beanFactoryToProcess, StringValueResolver valueResolver) {
                log.info("doProcessProperties");
                super.doProcessProperties(beanFactoryToProcess, valueResolver);
            }
        };
    }

    /**
     * Creates a CacheManager which allows the spring caching annotations to work
     * Annotations: Cacheable, CachePut and CacheEvict
     * http://spring.io/guides/gs/caching/
     */
    @Bean
    public CacheManager cacheManager() {
        return new ConcurrentMapCacheManager(); // not appropriate for production, try JCacheCacheManager or HazelcastCacheManager instead
    }

    /**
     * Allows access to the H2 console at: {server}/console/
     * Enter this as the JDBC URL: jdbc:h2:mem:AZ
     */
    @Bean
    public ServletRegistrationBean h2servletRegistration() {
        ServletRegistrationBean registration = new ServletRegistrationBean(new WebServlet());
        registration.addUrlMappings("/console/*");
        return registration;
    }

    // Spring Security

    @Autowired
    @Order(Ordered.HIGHEST_PRECEDENCE + 10)
    @SuppressWarnings("SpringJavaAutowiringInspection")
    public void configureSimpleAuthUsers(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("admin").password("admin").roles("ADMIN", "USER")
                .and().withUser("user").password("user").roles("USER");
    }

    @Configuration
    @Order(1) // HIGHEST
    public static class LTISecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
        private LTIOAuthProviderProcessingFilter ltioAuthProviderProcessingFilter;
        @Autowired
        LTIDataService ltiDataService;
        @Autowired
        LTIConsumerDetailsService oauthConsumerDetailsService;
        @Autowired
        MyOAuthNonceServices oauthNonceServices;
        @Autowired
        LTIOAuthAuthenticationHandler oauthAuthenticationHandler;
        @Autowired
        OAuthProcessingFilterEntryPoint oauthProcessingFilterEntryPoint;
        @Autowired
        OAuthProviderTokenServices oauthProviderTokenServices;

        @PostConstruct
        public void init() {
            ltioAuthProviderProcessingFilter = new LTIOAuthProviderProcessingFilter(ltiDataService, oauthConsumerDetailsService, oauthNonceServices, oauthProcessingFilterEntryPoint, oauthAuthenticationHandler, oauthProviderTokenServices);
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            /**/
            http.requestMatchers().antMatchers("/lti/**", "/lti2/**").and()
                    .addFilterBefore(ltioAuthProviderProcessingFilter, UsernamePasswordAuthenticationFilter.class)
                    .authorizeRequests().anyRequest().hasRole("LTI")
                    .and().csrf().disable().headers().frameOptions().disable();
            //NOTE: the .headers().frameOptions().disable(); is done to work with my local sakai without https... but that should be
            // configured correctly.

            /*
            http.antMatcher("/lti/**")
                    .addFilterBefore(ltioAuthProviderProcessingFilter, UsernamePasswordAuthenticationFilter.class)
                    .authorizeRequests().anyRequest().hasRole("LTI")
                    .and().csrf().disable(); // probably need https://github.com/spring-projects/spring-boot/issues/179
            /**/
        }
    }

    @Order(2) // HIGHER YET
    @Configuration
    // JavaConfig take on https://github.com/pac4j/spring-security-pac4j-demo/blob/master/src/main/resources/securityContext.xml
    public static class LTI3OidcAuthConfigurationAdapter extends WebSecurityConfigurerAdapter {

        @Autowired
        private LTIDataService ltiDataService;

        @Value("https://${server.name}:${server.port}/${server.servlet.context-path:}")
        private String baseUrl;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // this is open
            http.antMatcher("/oauth2/oidc/lti/**")
                    .exceptionHandling()
                        .authenticationEntryPoint(pac4jEntryPoint())
                    .and()
                        .addFilterBefore(newLti3OidcCallbackFilter(), BasicAuthenticationFilter.class)
                        .addFilterBefore(newLti3OidcSecurityFilter(), BasicAuthenticationFilter.class)
                        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                    .and()
                        .csrf()
                            .disable()
                        .headers()
                            .frameOptions()
                                .disable();

        }

        @Bean
        public AuthenticationEntryPoint pac4jEntryPoint() {
            return new Pac4jEntryPoint(pac4jConfig(), null);
        }

        // You do not want your Servlet filters to be Beans, else they'll be added to request handling chains twice,
        // once here (and on the path we actually want) and once by ServletContextInitializingBeans.addAdaptableBeans()
        // (to a root path we don't want)
        private SecurityFilter newLti3OidcSecurityFilter() {
            return new SecurityFilter(
                    pac4jConfig(),
                    "Pac4jOidcClient" // TODO having to know list of client names at app startup is potentially a problem long-term since a real LTI app will grow that list at runtime
            );
        }


        private CallbackFilter newLti3OidcCallbackFilter() {
            CallbackFilter callbackFilter = new CallbackFilter(pac4jConfig()) {
                // Only needed if Client names are in the path rather than as a query param, which we're currently
                // doing to try to rule out problems with query param encoding on the Platform side. Either way, there's
                // a potential problem if the Platform expects return URLs to be known statically per-Tool, no matter
                // how many times that Tool is registered with the platform (which may the case, for example, if
                // Tools are expected to publish static registration metadata as was the case in LTI 1.1)
                private final Matcher requestPathMatcher = new Matcher() {
                    private final AntPathMatcher antMatcher = new AntPathMatcher("/");

                    @Override
                    public boolean matches(WebContext context) {
                        return antMatcher.match("/oauth2/oidc/lti/authorization/**", context.getPath());
                    }
                };


                @Override
                protected boolean mustApply(final J2EContext context) {
                    return requestPathMatcher.matches(context);
                }
            };
            callbackFilter.setSuffix("/oauth2/oidc/lti/authorization");
            return callbackFilter;
        }

        @Bean
        public Config pac4jConfig() {
            return new Config(
                pac4jClients()
            );
        }

        @Bean
        public Clients pac4jClients() {
            // TODO this might need to change to be more dynamic since in the Real World, a new Client could be
            //  added at any time and we don't want to bounce the app to pick up such a change. There's a kinda-sorta
            //  example of what this could look like at https://github.com/jkacer/pac4j-extensions. (Still requires
            //  reload, but at least demos what a re-implementation of Clients entails.
            return new Clients(
                    baseUrl + "oauth2/oidc/lti/authorization",
                    newClient("Pac4jOidcClient", pacj4OidcConfiguration())
            );
        }

        private Client newClient(String name, OidcConfiguration config) {
            OidcClient client = new OidcClient<>(config);
            client.setName(name);
            client.setRedirectActionBuilder(new OidcRedirectActionBuilder(client.getConfiguration(), client) {
                @Override
                protected void addStateAndNonceParameters(final WebContext context, final Map<String, String> params) {
                    params.put("login_hint", context.getRequestParameter("login_hint"));
                    params.put("lti_message_hint", context.getRequestParameter("lti_message_hint"));
                    params.put("target_link_uri", context.getRequestParameter("target_link_uri"));
                    super.addStateAndNonceParameters(context, params);
                }
            });
            client.setCallbackUrlResolver(new PathParameterCallbackUrlResolver());
            client.setProfileCreator(new OidcProfileCreator<OidcProfile>(config) {
                @Override
                protected void internalInit() {
                    tokenValidator = new TokenValidator(configuration) {
                        @Override
                        protected IDTokenValidator createRSATokenValidator(final OidcConfiguration configuration,
                                                                           final JWSAlgorithm jwsAlgorithm, final ClientID clientID) {
                            return new IDTokenValidator(
                                    configuration.findProviderMetadata().getIssuer(),
                                    clientID,
                                    jwsAlgorithm,
                                    findKeySet(configuration.findProviderMetadata().getIssuer(), clientID));
                        }

                        private JWKSet findKeySet(Issuer issuer, ClientID clientId) {
                            // TODO change this to only return keys associated directly with a specific client
                            List<RSAKeyEntity> domainKeys = ltiDataService.getRepos().rsaKeys.findAll();
                            List<JWK> joseKeys = domainKeys.stream()
                                    .map(domainKey -> {
                                        try {
                                            return Pair.of(
                                                    domainKey.getKid(),
                                                    OAuthUtils.loadPublicKey(domainKey.getKeyKey())
                                            );
                                        } catch (Exception e) {
                                            logger.warn("Failed to deserialize public key [" + domainKey.getKid() + "]", e);
                                            return null;
                                        }
                                    })
                                    .filter(Objects::nonNull)
                                    .map(jdkKidAndKey -> new RSAKey.Builder(jdkKidAndKey.getRight())
                                            .keyID(jdkKidAndKey.getLeft().getKid()).build())
                                    .collect(Collectors.toList());
                            return new JWKSet(joseKeys);
                        }
                    };

                    super.internalInit();
                }
            });
            return client;
        }

        // TODO this needs to be per-Client, so will need to change to not be a bean (will probably be encapsulated
        //   behind a custom Clients impl that reads Clients from the db).
        @Bean
        public OidcConfiguration pacj4OidcConfiguration() {
            OidcConfiguration oidcConfiguration = new OidcConfiguration();

            oidcConfiguration.setScope(OIDCScopeValue.OPENID.getValue());
            oidcConfiguration.setClientId("dmccallum-platform-2-client-1"); // TODO clear example of why this needs to be more dynamic
//            oidcConfiguration.setClientId("dmccallum-local-platform-2-client-1"); // TODO clear example of why this needs to be more dynamic

            OIDCProviderMetadata oidcProviderMetadata = new OIDCProviderMetadata(
                    new Issuer("https://dmp2-lti-ri.imsglobal.org"), // TODO clear example of why this needs to be more dynamic
//                    new Issuer("http://localhost:3000"), // TODO clear example of why this needs to be more dynamic
                    ImmutableList.of(SubjectType.PUBLIC), // TODO not sure if this is right
                    URI.create("https://oauth2server.imsglobal.org/jwks") // TODO value definitely wrong... don't think IMS RI hosts its keys at a JWKS URL
            );
            oidcProviderMetadata.setAuthorizationEndpointURI(URI.create("https://lti-ri.imsglobal.org/platforms/110/authorizations/new"));
//            oidcProviderMetadata.setAuthorizationEndpointURI(URI.create("http://localhost:3000/platforms/2/authorizations/new"));
            oidcProviderMetadata.setIDTokenJWSAlgs(ImmutableList.of(JWSAlgorithm.RS256));
            oidcConfiguration.setProviderMetadata(oidcProviderMetadata);

            oidcConfiguration.setUseNonce(true); // TODO IMS-RI seems to always generate its own nonces
//            oidcConfiguration.setPreferredJwsAlgorithm(JWSAlgorithm.RS256); // TODO unsure if this is needed

            oidcConfiguration.setClientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC); // TODO this is not right but is the only way to get OidcAuthenticator to work... we'll need to provide our own impl of that
            oidcConfiguration.setSecret("thisiswrong"); // TODO also not right, same reason as setClientAuthenticationMethod()

            // TODO we'll also need to add in:
            //  - a StateGenerator
            //  - probably some CustomParams
            //  - probably a ProfileCreator
            //  Also don't know how nonce's are being validated and, more generally, how this works in a multi-server deployment

            // Enable Implicit flow
            oidcConfiguration.setResponseType("id_token");
            oidcConfiguration.setResponseMode("form_post");

            return oidcConfiguration;
        }

    }

    @Order(3) // VERY HIGH
    @Configuration
    public static class OICDAuthConfigurationAdapter extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // this is open
            http.antMatcher("/oidc/**").authorizeRequests().anyRequest().permitAll().and().csrf().disable().headers().frameOptions().disable();
        }
    }

    @Configuration
    @Order(7) // HIGH
    public static class LTI3SecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
        private LTI3OAuthProviderProcessingFilter lti3oAuthProviderProcessingFilter;
        @Autowired
        LTIDataService ltiDataService;
        @Autowired
        LTIJWTService ltijwtService;

        @PostConstruct
        public void init() {
            lti3oAuthProviderProcessingFilter = new LTI3OAuthProviderProcessingFilter(ltiDataService,ltijwtService);
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            /**/
            http.requestMatchers().antMatchers("/lti3/**").and()
                    .addFilterBefore(lti3oAuthProviderProcessingFilter, UsernamePasswordAuthenticationFilter.class)
                    .authorizeRequests().anyRequest().permitAll().and().csrf().disable().headers().frameOptions().disable();
            //NOTE: the .headers().frameOptions().disable(); is done to work with my local sakai without https... but that should be
            // configured correctly.

            /*
            http.antMatcher("/lti/**")
                    .addFilterBefore(ltioAuthProviderProcessingFilter, UsernamePasswordAuthenticationFilter.class)
                    .authorizeRequests().anyRequest().hasRole("LTI")
                    .and().csrf().disable(); // probably need https://github.com/spring-projects/spring-boot/issues/179
            /**/
        }
    }

    @Configuration
    @Order(11) // HIGH
    public static class OAuthSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
        private ZeroLeggedOAuthProviderProcessingFilter zeroLeggedOAuthProviderProcessingFilter;
        @Autowired
        MyConsumerDetailsService oauthConsumerDetailsService;
        @Autowired
        MyOAuthNonceServices oauthNonceServices;
        @Autowired
        MyOAuthAuthenticationHandler oauthAuthenticationHandler;
        @Autowired
        OAuthProcessingFilterEntryPoint oauthProcessingFilterEntryPoint;
        @Autowired
        OAuthProviderTokenServices oauthProviderTokenServices;

        @PostConstruct
        public void init() {
            // NOTE: have to build the filter here: http://stackoverflow.com/questions/24761194/how-do-i-stop-spring-filterregistrationbean-from-registering-my-filter-on/24762970
            zeroLeggedOAuthProviderProcessingFilter = new ZeroLeggedOAuthProviderProcessingFilter(oauthConsumerDetailsService, oauthNonceServices, oauthProcessingFilterEntryPoint, oauthAuthenticationHandler, oauthProviderTokenServices, false);
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.antMatcher("/oauth/**")
                    // added filters must be ordered: see http://docs.spring.io/spring-security/site/docs/3.2.0.RELEASE/apidocs/org/springframework/security/config/annotation/web/HttpSecurityBuilder.html#addFilter%28javax.servlet.Filter%29
                    .addFilterBefore(zeroLeggedOAuthProviderProcessingFilter, UsernamePasswordAuthenticationFilter.class)
                    .authorizeRequests().anyRequest().hasRole("OAUTH")
                    .and().csrf().disable(); // see above
        }
    }

    @Order(23) // MED
    @Configuration
    public static class FormLoginConfigurationAdapter extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.antMatcher("/form/**").authorizeRequests().anyRequest().authenticated()
                    .and().formLogin().permitAll().loginPage("/form/login").loginProcessingUrl("/form/login")
                    .and().logout().logoutUrl("/form/logout").invalidateHttpSession(true).logoutSuccessUrl("/");
        }
    }

    @Order(45) // LOW
    @Configuration
    public static class BasicAuthConfigurationAdapter extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // basic auth protection for the /basic path
            http.antMatcher("/basic/**").authorizeRequests().anyRequest().authenticated()
                    .and().httpBasic();
        }
    }

    @Order(67) // LOWEST
    @Configuration
    public static class NoAuthConfigurationAdapter extends WebSecurityConfigurerAdapter {
        @Override
        public void configure(WebSecurity web) throws Exception {
            web.ignoring().antMatchers("/console/**");
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // this ensures security context info (Principal, sec:authorize, etc.) is accessible on all paths
            http.antMatcher("/**").authorizeRequests().anyRequest().permitAll().and().headers().frameOptions().disable();
        }
    }

    // OAuth beans

    @Bean(name = "oauthProviderTokenServices")
    public OAuthProviderTokenServices oauthProviderTokenServices() {
        // NOTE: we don't use the OAuthProviderTokenServices for 0-legged but it cannot be null
        return new InMemoryProviderTokenServices();
    }

}
