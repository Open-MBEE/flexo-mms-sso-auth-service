package org.openmbee.flexo.mms.sso.oauth;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CimdClientResolverTest {

    private HttpServer server;

    @AfterEach
    void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    private static CimdClientResolver resolver(boolean dev, List<String> allowedHosts) {
        OAuthServerProperties props = new OAuthServerProperties();
        props.getCimd().setEnabled(true);
        props.getCimd().setAllowHttp(dev);
        props.getCimd().setAllowPrivateAddresses(dev);
        props.getCimd().setAllowedHosts(allowedHosts);
        props.getCimd().setMaxBytes(512);
        return new CimdClientResolver(props);
    }

    private String serve(int status, String body, String location) throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/client", exchange -> {
            byte[] bytes = body.replace("SELF", url()).getBytes(StandardCharsets.UTF_8);
            if (location != null) {
                exchange.getResponseHeaders().add("Location", location);
            }
            exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
            if (bytes.length > 0) {
                exchange.getResponseBody().write(bytes);
            }
            exchange.close();
        });
        server.start();
        return url();
    }

    private String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/client";
    }

    @Test
    void resolvesValidDocument() throws Exception {
        String id = serve(200, "{\"client_id\":\"SELF\",\"client_name\":\"Test\",\"redirect_uris\":[\"http://localhost/cb\"]}", null);
        OAuthClient client = resolver(true, List.of()).resolve(id).orElseThrow();
        assertThat(client.displayName()).isEqualTo("Test");
        assertThat(client.metadataDocument()).isTrue();
        assertThat(client.isConfidential()).isFalse();
        assertThat(client.allowsRedirectUri("http://localhost:3334/cb")).isTrue();
        assertThat(client.allowsRedirectUri("http://localhost/other")).isFalse();
    }

    @Test
    void rejectsMismatchedClientId() throws Exception {
        String id = serve(200, "{\"client_id\":\"https://other.example/client\",\"redirect_uris\":[\"http://localhost/cb\"]}", null);
        assertThatThrownBy(() -> resolver(true, List.of()).resolve(id)).hasMessageContaining("does not match");
    }

    @Test
    void rejectsConfidentialOrDangerousDocuments() throws Exception {
        String id = serve(200, "{\"client_id\":\"SELF\",\"token_endpoint_auth_method\":\"client_secret_basic\",\"redirect_uris\":[\"http://localhost/cb\"]}", null);
        assertThatThrownBy(() -> resolver(true, List.of()).resolve(id)).hasMessageContaining("public clients");
        assertThat(CimdClientResolver.isAcceptableRedirectUri("javascript:alert(1)")).isFalse();
        assertThat(CimdClientResolver.isAcceptableRedirectUri("http://evil.example/cb")).isFalse();
        assertThat(CimdClientResolver.isAcceptableRedirectUri("https://ok.example/cb")).isTrue();
        assertThat(CimdClientResolver.isAcceptableRedirectUri("cursor://callback")).isTrue();
    }

    @Test
    void rejectsOversizedDocuments() throws Exception {
        String id = serve(200, "{\"client_id\":\"SELF\",\"pad\":\"" + "x".repeat(600) + "\"}", null);
        assertThatThrownBy(() -> resolver(true, List.of()).resolve(id)).hasMessageContaining("exceeds");
    }

    @Test
    void doesNotFollowRedirects() throws Exception {
        String id = serve(302, "", "http://169.254.169.254/latest/meta-data");
        assertThatThrownBy(() -> resolver(true, List.of()).resolve(id)).hasMessageContaining("HTTP 302");
    }

    @Test
    void productionDefaultsBlockHttpAndPrivateAddresses() {
        CimdClientResolver strict = resolver(false, List.of());
        assertThat(strict.resolve("http://127.0.0.1/client")).isEmpty();
        assertThatThrownBy(() -> strict.resolve("https://127.0.0.1/client")).hasMessageContaining("non-public");
        assertThatThrownBy(() -> strict.resolve("https://10.1.2.3/client")).hasMessageContaining("non-public");
        assertThatThrownBy(() -> strict.resolve("https://example.com/")).hasMessageContaining("path");
        assertThatThrownBy(() -> strict.resolve("https://user@example.com/c")).hasMessageContaining("credentials");
    }

    @Test
    void enforcesHostAllowList() {
        CimdClientResolver allowList = resolver(false, List.of("*.trusted.example", "mcp.example"));
        assertThatThrownBy(() -> allowList.resolve("https://evil.example/client")).hasMessageContaining("not allowed");
        assertThat(allowList.validateClientIdUrl("https://a.trusted.example/client").getHost()).isEqualTo("a.trusted.example");
        assertThat(allowList.validateClientIdUrl("https://mcp.example/client").getHost()).isEqualTo("mcp.example");
    }

    @Test
    void classifiesNonPublicAddresses() throws Exception {
        assertThat(CimdClientResolver.isNonPublic(InetAddress.getByName("100.64.1.1"))).isTrue();
        assertThat(CimdClientResolver.isNonPublic(InetAddress.getByName("fd00::1"))).isTrue();
        assertThat(CimdClientResolver.isNonPublic(InetAddress.getByName("192.168.0.1"))).isTrue();
        assertThat(CimdClientResolver.isNonPublic(InetAddress.getByName("8.8.8.8"))).isFalse();
    }
}
