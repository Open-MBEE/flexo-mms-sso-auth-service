package org.openmbee.flexo.mms.sso.oauth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.openmbee.flexo.mms.sso.config.TestSecurityConfig;
import org.openmbee.flexo.mms.sso.service.RefreshTokenService;
import org.openmbee.flexo.mms.sso.service.TokenSigner;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:sqlite:build/oauth-flow-test-${random.uuid}.db",
        "jwt.algorithm=RS256",
        "jwt.domain=https://auth.test",
        "jwt.audience=layer1-audience",
        "flexo.sso-auth-service.sso_user_id_field=sid",
        "flexo.sso-auth-service.oauth.issuer=https://auth.test/sso",
        "flexo.sso-auth-service.oauth.resources=https://mcp.test/mcp",
        "flexo.sso-auth-service.oauth.cimd.enabled=true",
        "flexo.sso-auth-service.oauth.cimd.allow_http=true",
        "flexo.sso-auth-service.oauth.cimd.allow_private_addresses=true",
        "flexo.sso-auth-service.oauth.clients[0].client_id=trusted-public",
        "flexo.sso-auth-service.oauth.clients[0].redirect_uris=http://127.0.0.1/callback",
        "flexo.sso-auth-service.oauth.clients[0].trusted=true",
        "flexo.sso-auth-service.oauth.clients[1].client_id=confidential",
        "flexo.sso-auth-service.oauth.clients[1].client_secret={noop}s3cret",
        "flexo.sso-auth-service.oauth.clients[1].name=Confidential Client",
        "flexo.sso-auth-service.oauth.clients[1].redirect_uris=https://client.test/cb",
        "flexo.sso-auth-service.oauth.clients[2].client_id=untrusted",
        "flexo.sso-auth-service.oauth.clients[2].name=Untrusted Client",
        "flexo.sso-auth-service.oauth.clients[2].redirect_uris=https://untrusted.test/cb"
})
@AutoConfigureMockMvc
@Import(TestSecurityConfig.class)
@ActiveProfiles("test")
class OAuthAuthorizationFlowTest {

    private static final String RESOURCE = "https://mcp.test/mcp";
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final HttpServer CIMD_SERVER = startCimdServer();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TokenSigner tokenSigner;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    private final ObjectMapper mapper = new ObjectMapper();

    @AfterAll
    static void stopServer() {
        CIMD_SERVER.stop(0);
    }

    @Test
    void metadataAdvertisesEndpoints() throws Exception {
        mockMvc.perform(get("/.well-known/oauth-authorization-server"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("https://auth.test/sso"))
                .andExpect(jsonPath("$.authorization_endpoint").value("https://auth.test/sso/oauth/authorize"))
                .andExpect(jsonPath("$.token_endpoint").value("https://auth.test/sso/token"))
                .andExpect(jsonPath("$.jwks_uri").value("https://auth.test/sso/.well-known/jwks.json"))
                .andExpect(jsonPath("$.code_challenge_methods_supported[0]").value("S256"))
                .andExpect(jsonPath("$.client_id_metadata_document_supported").value(true));
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("https://auth.test/sso"));
    }

    @Test
    void unauthenticatedAuthorizeRedirectsToSsoLogin() throws Exception {
        mockMvc.perform(authorizeRequest("trusted-public", "http://127.0.0.1:5555/callback"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", org.hamcrest.Matchers.containsString("/oauth2/authorization/oidc")));
    }

    @Test
    void fullFlowIssuesLayer1CompatibleTokensAndRotatesRefresh() throws Exception {
        String redirect = "http://127.0.0.1:5555/callback";
        Map<String, String> callback = authorizeAndGetCallback("trusted-public", redirect, "alice");
        assertThat(callback.get("state")).isEqualTo("xyz");
        assertThat(callback.get("iss")).isEqualTo("https://auth.test/sso");

        JsonNode tokens = exchangeCode(callback.get("code"), "trusted-public", redirect, VERIFIER)
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andReturnJson();

        DecodedJWT access = verify(tokens.get("access_token").asString());
        assertThat(access.getAudience()).containsExactly("layer1-audience", RESOURCE);
        assertThat(access.getIssuer()).isEqualTo("https://auth.test");
        assertThat(access.getClaim("username").asString()).isEqualTo("alice");
        assertThat(access.getClaim("groups").asList(String.class)).containsExactly("engineers");
        assertThat(access.getClaim("client_id").asString()).isEqualTo("trusted-public");

        String refresh = tokens.get("refresh_token").asString();
        JsonNode refreshed = token(Map.of("grant_type", "refresh_token", "refresh_token", refresh,
                "client_id", "trusted-public")).andExpect(status().isOk()).andReturnJson();
        assertThat(verify(refreshed.get("access_token").asString()).getAudience()).contains(RESOURCE);

        // reusing the rotated token revokes the whole chain
        token(Map.of("grant_type", "refresh_token", "refresh_token", refresh, "client_id", "trusted-public"))
                .andExpect(jsonPath("$.error").value("invalid_grant"));
        token(Map.of("grant_type", "refresh_token", "refresh_token", refreshed.get("refresh_token").asString(),
                "client_id", "trusted-public"))
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    void codeIsSingleUseAndReplayRevokesIssuedTokens() throws Exception {
        String redirect = "http://127.0.0.1/callback";
        String code = authorizeAndGetCallback("trusted-public", redirect, "bob").get("code");
        JsonNode tokens = exchangeCode(code, "trusted-public", redirect, VERIFIER).andExpect(status().isOk()).andReturnJson();

        exchangeCode(code, "trusted-public", redirect, VERIFIER)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
        token(Map.of("grant_type", "refresh_token", "refresh_token", tokens.get("refresh_token").asString(),
                "client_id", "trusted-public"))
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    void wrongPkceVerifierOrRedirectIsRejected() throws Exception {
        String redirect = "http://127.0.0.1/callback";
        String code = authorizeAndGetCallback("trusted-public", redirect, "carol").get("code");
        exchangeCode(code, "trusted-public", redirect, "x".repeat(43))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
        // a failed attempt does not consume the code
        exchangeCode(code, "trusted-public", redirect, VERIFIER).andExpect(status().isOk());

        String code2 = authorizeAndGetCallback("trusted-public", redirect, "carol").get("code");
        exchangeCode(code2, "trusted-public", "http://127.0.0.1/other", VERIFIER)
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    void unregisteredRedirectUriShowsErrorPageWithoutRedirecting() throws Exception {
        mockMvc.perform(authorizeRequest("trusted-public", "https://evil.test/cb").with(user("alice")))
                .andExpect(status().isBadRequest())
                .andExpect(view().name("oauth-error"))
                .andExpect(header().doesNotExist("Location"));
        mockMvc.perform(authorizeRequest("nope", "https://evil.test/cb").with(user("alice")))
                .andExpect(status().isBadRequest())
                .andExpect(view().name("oauth-error"));
    }

    @Test
    void protocolErrorsAreReturnedToTheClient() throws Exception {
        MvcResult noPkce = mockMvc.perform(get("/oauth/authorize")
                        .param("client_id", "trusted-public").param("redirect_uri", "http://127.0.0.1/callback")
                        .param("response_type", "code").param("state", "s1").with(user("alice")))
                .andExpect(status().isFound()).andReturn();
        assertThat(query(noPkce)).containsEntry("error", "invalid_request").containsEntry("state", "s1");

        MvcResult badResource = mockMvc.perform(authorizeRequest("trusted-public", "http://127.0.0.1/callback")
                        .param("resource", "https://other.test/mcp").with(user("alice")))
                .andExpect(status().isFound()).andReturn();
        assertThat(query(badResource)).containsEntry("error", "invalid_target");
    }

    @Test
    void untrustedClientRequiresConsent() throws Exception {
        String redirect = "https://untrusted.test/cb";
        MockHttpSession session = new MockHttpSession();
        MvcResult page = mockMvc.perform(authorizeRequest("untrusted", redirect).session(session).with(user("dave")))
                .andExpect(status().isOk())
                .andExpect(view().name("oauth-consent"))
                .andExpect(model().attribute("clientName", "Untrusted Client"))
                .andReturn();
        String requestId = (String) page.getModelAndView().getModel().get("requestId");

        // CSRF-protected
        mockMvc.perform(post("/oauth/authorize/consent").session(session).with(user("dave"))
                        .param("request_id", requestId).param("decision", "approve"))
                .andExpect(status().isForbidden());

        MvcResult approved = mockMvc.perform(post("/oauth/authorize/consent").session(session).with(user("dave")).with(csrf())
                        .param("request_id", requestId).param("decision", "approve"))
                .andExpect(status().isFound()).andReturn();
        assertThat(approved.getResponse().getHeader("Location")).startsWith(redirect + "?code=");
        exchangeCode(query(approved).get("code"), "untrusted", redirect, VERIFIER).andExpect(status().isOk());

        MvcResult page2 = mockMvc.perform(authorizeRequest("untrusted", redirect).session(session).with(user("dave")))
                .andExpect(status().isOk()).andReturn();
        MvcResult denied = mockMvc.perform(post("/oauth/authorize/consent").session(session).with(user("dave")).with(csrf())
                        .param("request_id", (String) page2.getModelAndView().getModel().get("requestId"))
                        .param("decision", "deny"))
                .andExpect(status().isFound()).andReturn();
        assertThat(query(denied)).containsEntry("error", "access_denied").containsEntry("state", "xyz");
    }

    @Test
    void confidentialClientMustAuthenticate() throws Exception {
        String redirect = "https://client.test/cb";
        String code = consentAndGetCode("confidential", redirect, "erin");

        exchangeCode(code, "confidential", redirect, VERIFIER)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));

        String code2 = consentAndGetCode("confidential", redirect, "erin");
        String basic = "Basic " + Base64.getEncoder().encodeToString("confidential:s3cret".getBytes(StandardCharsets.UTF_8));
        JsonNode tokens = json(mockMvc.perform(form(Map.of("grant_type", "authorization_code", "code", code2,
                        "redirect_uri", redirect, "code_verifier", VERIFIER)).header("Authorization", basic))
                .andExpect(status().isOk()).andReturn());

        // refresh bound to the client: other/no client is rejected, the owner succeeds
        token(Map.of("grant_type", "refresh_token", "refresh_token", tokens.get("refresh_token").asString()))
                .andExpect(jsonPath("$.error").value("invalid_client"));
        token(Map.of("grant_type", "refresh_token", "refresh_token", tokens.get("refresh_token").asString(),
                "client_id", "trusted-public"))
                .andExpect(jsonPath("$.error").value("invalid_grant"));
        JsonNode refreshed = json(mockMvc.perform(form(Map.of("grant_type", "refresh_token",
                        "refresh_token", tokens.get("refresh_token").asString())).header("Authorization", basic))
                .andExpect(status().isOk()).andReturn());

        // revocation kills the chain
        mockMvc.perform(post("/oauth/revoke").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("token", refreshed.get("refresh_token").asString()).header("Authorization", basic))
                .andExpect(status().isOk());
        mockMvc.perform(form(Map.of("grant_type", "refresh_token",
                        "refresh_token", refreshed.get("refresh_token").asString())).header("Authorization", basic))
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    void clientIdMetadataDocumentClient() throws Exception {
        String clientId = cimdClientId();
        String redirect = "http://127.0.0.1:7777/cb";
        MockHttpSession session = new MockHttpSession();
        MvcResult page = mockMvc.perform(authorizeRequest(clientId, redirect).session(session).with(user("frank")))
                .andExpect(status().isOk())
                .andExpect(model().attribute("clientName", "CIMD Test Client"))
                .andExpect(model().attribute("metadataDocument", true))
                .andReturn();
        MvcResult approved = mockMvc.perform(post("/oauth/authorize/consent").session(session).with(user("frank")).with(csrf())
                        .param("request_id", (String) page.getModelAndView().getModel().get("requestId"))
                        .param("decision", "approve"))
                .andExpect(status().isFound()).andReturn();
        exchangeCode(query(approved).get("code"), clientId, redirect, VERIFIER).andExpect(status().isOk());
    }

    @Test
    void legacyRefreshChainsKeepSingleAudience() throws Exception {
        String refresh = refreshTokenService.issue("legacy-user").value();
        JsonNode tokens = token(Map.of("grant_type", "refresh_token", "refresh_token", refresh))
                .andExpect(status().isOk()).andReturnJson();
        DecodedJWT access = verify(tokens.get("access_token").asString());
        assertThat(access.getAudience()).containsExactly("layer1-audience");
        assertThat(access.getClaim("client_id").isMissing()).isTrue();
    }

    // --- helpers ---

    private static org.springframework.test.web.servlet.request.RequestPostProcessor user(String sid) {
        return oidcLogin().idToken(t -> t.subject("sub-" + sid).claim("sid", sid).claim("groups", List.of("engineers")));
    }

    private MockHttpServletRequestBuilder authorizeRequest(String clientId, String redirectUri) {
        return get("/oauth/authorize")
                .param("response_type", "code")
                .param("client_id", clientId)
                .param("redirect_uri", redirectUri)
                .param("code_challenge", CHALLENGE)
                .param("code_challenge_method", "S256")
                .param("resource", RESOURCE)
                .param("state", "xyz");
    }

    private Map<String, String> authorizeAndGetCallback(String clientId, String redirect, String sid) throws Exception {
        MvcResult result = mockMvc.perform(authorizeRequest(clientId, redirect).with(user(sid)))
                .andExpect(status().isFound()).andReturn();
        assertThat(result.getResponse().getHeader("Location")).startsWith(redirect + "?");
        return query(result);
    }

    private String consentAndGetCode(String clientId, String redirect, String sid) throws Exception {
        MockHttpSession session = new MockHttpSession();
        MvcResult page = mockMvc.perform(authorizeRequest(clientId, redirect).session(session).with(user(sid)))
                .andExpect(status().isOk()).andReturn();
        MvcResult approved = mockMvc.perform(post("/oauth/authorize/consent").session(session).with(user(sid)).with(csrf())
                        .param("request_id", (String) page.getModelAndView().getModel().get("requestId"))
                        .param("decision", "approve"))
                .andExpect(status().isFound()).andReturn();
        return query(approved).get("code");
    }

    private JsonResult exchangeCode(String code, String clientId, String redirect, String verifier) throws Exception {
        return token(Map.of("grant_type", "authorization_code", "code", code, "client_id", clientId,
                "redirect_uri", redirect, "code_verifier", verifier, "resource", RESOURCE));
    }

    private JsonResult token(Map<String, String> params) throws Exception {
        return new JsonResult(mockMvc.perform(form(params)));
    }

    private MockHttpServletRequestBuilder form(Map<String, String> params) {
        MockHttpServletRequestBuilder builder = post("/token").contentType(MediaType.APPLICATION_FORM_URLENCODED);
        params.forEach(builder::param);
        return builder;
    }

    private class JsonResult {
        private final org.springframework.test.web.servlet.ResultActions actions;

        JsonResult(org.springframework.test.web.servlet.ResultActions actions) {
            this.actions = actions;
        }

        JsonResult andExpect(org.springframework.test.web.servlet.ResultMatcher matcher) throws Exception {
            actions.andExpect(matcher);
            return this;
        }

        JsonNode andReturnJson() throws Exception {
            return json(actions.andReturn());
        }
    }

    private JsonNode json(MvcResult result) throws Exception {
        return mapper.readTree(result.getResponse().getContentAsString());
    }

    private static Map<String, String> query(MvcResult result) {
        String location = result.getResponse().getHeader("Location");
        return UriComponentsBuilder.fromUriString(location).build().getQueryParams().toSingleValueMap()
                .entrySet().stream().collect(java.util.stream.Collectors.toMap(Map.Entry::getKey,
                        e -> java.net.URLDecoder.decode(e.getValue(), StandardCharsets.UTF_8)));
    }

    @SuppressWarnings("unchecked")
    private DecodedJWT verify(String token) throws Exception {
        Map<String, Object> jwk = ((List<Map<String, Object>>) tokenSigner.jwks().get("keys")).get(0);
        Base64.Decoder d = Base64.getUrlDecoder();
        RSAPublicKey key = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
                new BigInteger(1, d.decode((String) jwk.get("n"))), new BigInteger(1, d.decode((String) jwk.get("e")))));
        return JWT.require(Algorithm.RSA256(key, null)).withIssuer("https://auth.test").build().verify(token);
    }

    private static String cimdClientId() {
        return "http://127.0.0.1:" + CIMD_SERVER.getAddress().getPort() + "/client.json";
    }

    private static HttpServer startCimdServer() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/client.json", exchange -> {
                String id = "http://127.0.0.1:" + server.getAddress().getPort() + "/client.json";
                byte[] body = ("{\"client_id\":\"" + id + "\",\"client_name\":\"CIMD Test Client\","
                        + "\"redirect_uris\":[\"http://127.0.0.1/cb\"],\"token_endpoint_auth_method\":\"none\"}")
                        .getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.close();
            });
            server.start();
            return server;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
