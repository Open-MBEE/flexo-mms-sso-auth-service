package org.openmbee.flexo.mms.sso.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * Central authority for minting layer1-compatible JWTs.
 *
 * Supports two signing modes:
 *   - HS256 (default): shared-secret HMAC, byte-compatible with the legacy flexo-mms-auth-service tokens.
 *   - RS256: asymmetric signing with the public key published at /.well-known/jwks.json, allowing layer1
 *     (and any other verifier) to validate tokens without holding a secret capable of forging them.
 *
 * The token claim contract is intentionally unchanged: "username" and "groups".
 */
@Service
public class TokenSigner {

    private static final Logger log = LoggerFactory.getLogger(TokenSigner.class);

    @Value("${jwt.domain:http://localhost:8080}")
    private String issuer;

    @Value("${jwt.audience:flexo-mms-api}")
    private String audience;

    @Value("${jwt.secret:flexo-mms-secret}")
    private String secret;

    /** "HS256" (default, legacy shared secret) or "RS256" (asymmetric + JWKS). */
    @Value("${jwt.algorithm:HS256}")
    private String algorithmName;

    /** Optional PKCS#8 PEM RSA private key. If RS256 is selected and this is empty, an ephemeral keypair is generated. */
    @Value("${jwt.rsa.private_key:}")
    private String rsaPrivateKeyPem;

    private Algorithm algorithm;
    private RSAPublicKey publicKey;
    private String keyId;

    @PostConstruct
    void init() {
        if ("RS256".equalsIgnoreCase(algorithmName)) {
            try {
                RSAPrivateKey privateKey;
                if (rsaPrivateKeyPem != null && !rsaPrivateKeyPem.isBlank()) {
                    privateKey = loadPrivateKey(rsaPrivateKeyPem);
                    publicKey = derivePublicKey(privateKey);
                } else {
                    log.warn("jwt.algorithm=RS256 but no jwt.rsa.private_key configured; "
                            + "generating an EPHEMERAL keypair (tokens will not survive restarts, "
                            + "and multiple replicas will not share keys)");
                    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                    generator.initialize(2048);
                    KeyPair pair = generator.generateKeyPair();
                    privateKey = (RSAPrivateKey) pair.getPrivate();
                    publicKey = (RSAPublicKey) pair.getPublic();
                }
                keyId = fingerprint(publicKey);
                algorithm = Algorithm.RSA256(publicKey, privateKey);
                log.info("Token signing configured: RS256, kid={}", keyId);
            } catch (Exception e) {
                throw new IllegalStateException("Failed to initialize RS256 token signing", e);
            }
        } else {
            algorithm = Algorithm.HMAC256(secret);
            log.info("Token signing configured: HS256 (shared secret)");
        }
    }

    /**
     * Mint a layer1-compatible JWT with the standard claim contract.
     */
    public String sign(String username, List<String> groups, long durationMs) {
        JWTCreator.Builder builder = JWT.create()
                .withAudience(audience)
                .withIssuer(issuer)
                .withClaim("username", username)
                .withClaim("groups", groups)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + durationMs));

        if (keyId != null) {
            builder.withKeyId(keyId);
        }

        return builder.sign(algorithm);
    }

    /**
     * JWK Set document for /.well-known/jwks.json. Empty key list when signing with HS256.
     */
    public Map<String, Object> jwks() {
        if (publicKey == null) {
            return Map.of("keys", Collections.emptyList());
        }

        Base64.Encoder b64url = Base64.getUrlEncoder().withoutPadding();
        Map<String, Object> jwk = Map.of(
                "kty", "RSA",
                "use", "sig",
                "alg", "RS256",
                "kid", keyId,
                "n", b64url.encodeToString(unsignedBytes(publicKey.getModulus().toByteArray())),
                "e", b64url.encodeToString(unsignedBytes(publicKey.getPublicExponent().toByteArray()))
        );

        return Map.of("keys", List.of(jwk));
    }

    private static RSAPrivateKey loadPrivateKey(String pem) throws Exception {
        String body = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(body);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private static RSAPublicKey derivePublicKey(RSAPrivateKey privateKey) throws Exception {
        if (!(privateKey instanceof RSAPrivateCrtKey crtKey)) {
            throw new IllegalArgumentException("RSA private key must be a CRT key to derive its public key");
        }
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) factory.generatePublic(
                new RSAPublicKeySpec(crtKey.getModulus(), crtKey.getPublicExponent()));
    }

    private static String fingerprint(RSAPublicKey key) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(key.getEncoded());
        return HexFormat.of().formatHex(hash, 0, 8);
    }

    /** Strip the sign byte that BigInteger.toByteArray() may prepend. */
    private static byte[] unsignedBytes(byte[] bytes) {
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return bytes;
    }
}
