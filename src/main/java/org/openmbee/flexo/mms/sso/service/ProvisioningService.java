package org.openmbee.flexo.mms.sso.service;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Automatic org / group / policy provisioning against layer1.
 *
 * IdP group names matching {@code org_group_pattern} (with named capture groups {@code org} and
 * {@code role}) drive idempotent creation of:
 *
 *   PUT /orgs/{org}                      (If-None-Match: *)
 *   PUT /groups/{idp-group-name}         (If-None-Match: *)   mms:id == the literal IdP group string
 *   PUT /policies/AutoProv-{org}-{role}  (If-None-Match: *)   subject=group, scope=org, roles per role_map
 *
 * All requests are create-only (If-None-Match: *): resources an admin has since customized are never
 * overwritten. 409/412 responses are treated as "already exists" and cached.
 *
 * The provisioner authenticates to layer1 with a self-minted short-lived service token whose groups
 * claim contains the SuperAdmins group id (default "super_admins"), which cluster.trig grants
 * cluster-scope admin roles — no layer1 bootstrap changes required.
 *
 * Provisioning failures are logged but never fail token issuance: the token remains valid, the user
 * simply lacks access until the next issuance retries provisioning.
 */
@Service
public class ProvisioningService {

    private static final Logger log = LoggerFactory.getLogger(ProvisioningService.class);

    /** Mirrors layer1's LDAP_COMPATIBLE_SLUG_REGEX. */
    private static final Pattern LAYER1_SLUG = Pattern.compile("[/?&=,._\\p{L}0-9-]{3,256}");

    /** Stricter charset for org ids since they become URL path segments and IRIs. */
    private static final Pattern ORG_SLUG = Pattern.compile("[a-zA-Z0-9._-]{3,64}");

    private static final String MMS_ROLE_PREFIX = "https://mms.openmbee.org/rdf/objects/Role.";

    private static final String DEFAULT_ROLE_MAP =
            "admin:AdminOrg AdminRepo AdminCollection AdminBranch AdminLock AdminArtifact AdminScratch AdminCommit AdminModel AdminMetadata;"
            + "contributor:ReadOrg WriteRepo WriteCollection WriteBranch WriteLock WriteArtifact WriteScratch WriteCommit WriteModel WriteMetadata;"
            + "reader:ReadOrg ReadRepo ReadCollection ReadBranch ReadLock ReadArtifact ReadScratch ReadCommit ReadModel ReadMetadata";

    @Value("${flexo.sso-auth-service.provisioning.enabled:false}")
    private boolean enabled;

    /** Base URL used to reach layer1 over the network, e.g. http://layer1-service:8080 */
    @Value("${flexo.sso-auth-service.provisioning.layer1_url:}")
    private String layer1Url;

    /** Layer1's FLEXO_MMS_ROOT_CONTEXT, used to construct resource IRIs. Defaults to layer1_url. */
    @Value("${flexo.sso-auth-service.provisioning.root_context:}")
    private String rootContext;

    /** Regex with named groups "org" and "role", e.g. ^flexo-(?<org>[a-z0-9-]{3,32})-(?<role>admin|contributor|reader)$ */
    @Value("${flexo.sso-auth-service.org_group_pattern:}")
    private String orgGroupPattern;

    /** role tier -> whitespace-separated layer1 Role names; tiers separated by ';', tier and roles by ':' */
    @Value("${flexo.sso-auth-service.provisioning.role_map:" + DEFAULT_ROLE_MAP + "}")
    private String roleMapSpec;

    @Value("${flexo.sso-auth-service.provisioning.cache_ttl_seconds:3600}")
    private long cacheTtlSeconds;

    @Value("${flexo.sso-auth-service.provisioning.service_username:sso-provisioner}")
    private String serviceUsername;

    /** Must match the mms:id of the bootstrap SuperAdmins group in cluster.trig. */
    @Value("${flexo.sso-auth-service.provisioning.super_admins_group_id:super_admins}")
    private String superAdminsGroupId;

    private final TokenSigner tokenSigner;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    private Pattern pattern;
    private Map<String, List<String>> roleMap = new HashMap<>();

    /** cache key "org|role" -> provisioned-at instant */
    private final ConcurrentHashMap<String, Instant> provisioned = new ConcurrentHashMap<>();

    public ProvisioningService(TokenSigner tokenSigner) {
        this.tokenSigner = tokenSigner;
    }

    @PostConstruct
    void init() {
        if (!enabled) {
            return;
        }
        if (orgGroupPattern == null || orgGroupPattern.isBlank()) {
            log.warn("Provisioning enabled but flexo.sso-auth-service.org_group_pattern is empty; disabling");
            enabled = false;
            return;
        }
        if (layer1Url == null || layer1Url.isBlank()) {
            log.warn("Provisioning enabled but flexo.sso-auth-service.provisioning.layer1_url is empty; disabling");
            enabled = false;
            return;
        }
        pattern = Pattern.compile(orgGroupPattern);
        roleMap = parseRoleMap(roleMapSpec);
        log.info("Org provisioning enabled: pattern={}, tiers={}", orgGroupPattern, roleMap.keySet());
    }

    /**
     * Ensure orgs/groups/policies exist for every org-encoding group in the list.
     * Never throws; failures are logged and retried on the next token issuance.
     */
    public void provisionForGroups(List<String> groups) {
        if (!enabled || groups == null || groups.isEmpty()) {
            return;
        }

        Set<OrgRole> targets = new LinkedHashSet<>();
        for (String group : groups) {
            Matcher matcher = pattern.matcher(group);
            if (!matcher.matches()) {
                continue;
            }
            String org;
            String role;
            try {
                org = matcher.group("org");
                role = matcher.group("role");
            } catch (IllegalArgumentException e) {
                // pattern lacks the required named capture groups; never fail token issuance over it
                log.error("org_group_pattern must define named capture groups 'org' and 'role'");
                return;
            }
            if (org == null || role == null) {
                continue;
            }
            if (!ORG_SLUG.matcher(org).matches() || !LAYER1_SLUG.matcher(group).matches()) {
                log.warn("Skipping provisioning for group '{}': org or group name fails slug validation", group);
                continue;
            }
            if (!roleMap.containsKey(role)) {
                log.warn("Skipping provisioning for group '{}': role tier '{}' not in role_map", group, role);
                continue;
            }
            targets.add(new OrgRole(org, role, group));
        }

        Instant staleBefore = Instant.now().minusSeconds(cacheTtlSeconds);
        for (OrgRole target : targets) {
            String cacheKey = target.org() + "|" + target.role();
            Instant last = provisioned.get(cacheKey);
            if (last != null && last.isAfter(staleBefore)) {
                continue;
            }
            try {
                ensure(target);
                provisioned.put(cacheKey, Instant.now());
            } catch (Exception e) {
                log.error("Provisioning failed for org={} role={} group={}: {}",
                        target.org(), target.role(), target.group(), e.getMessage());
            }
        }
    }

    private void ensure(OrgRole target) throws Exception {
        String token = tokenSigner.sign(serviceUsername, List.of(superAdminsGroupId), 60_000);
        String root = (rootContext == null || rootContext.isBlank() ? layer1Url : rootContext)
                .replaceAll("/+$", "");

        // 1. org
        put(token, "/orgs/" + target.org(), String.format(
                "<> <http://purl.org/dc/terms/title> \"%s (auto-provisioned)\"@en .", target.org()));

        // 2. group whose mms:id (== URL slug) is the literal IdP group string
        put(token, "/groups/" + target.group(), String.format(
                "<> <http://purl.org/dc/terms/title> \"%s (auto-provisioned)\"@en .", target.group()));

        // 3. org-scoped policy binding the group to its roles
        String roleIris = roleMap.get(target.role()).stream()
                .map(role -> "<" + MMS_ROLE_PREFIX + role + ">")
                .collect(Collectors.joining(", "));
        String policyBody = String.format(
                "@prefix mms: <https://mms.openmbee.org/rdf/ontology/> .%n"
                + "<>%n"
                + "    mms:subject <%s/groups/%s> ;%n"
                + "    mms:scope <%s/orgs/%s> ;%n"
                + "    mms:role %s ;%n"
                + "    .",
                root, target.group(), root, target.org(), roleIris);
        put(token, "/policies/AutoProv-" + target.org() + "-" + target.role(), policyBody);

        log.info("Provisioned org={} role={} for group '{}'", target.org(), target.role(), target.group());
    }

    private void put(String token, String path, String turtleBody) throws Exception {
        String base = layer1Url.replaceAll("/+$", "");
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(base + path))
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "text/turtle")
                // create-only semantics: never overwrite a resource an admin may have customized
                .header("If-None-Match", "*")
                .PUT(HttpRequest.BodyPublishers.ofString(turtleBody))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        int status = response.statusCode();

        // 2xx: created; 409/412: already exists (both acceptable outcomes for create-only PUT)
        if (status / 100 == 2 || status == 409 || status == 412 || status == 304) {
            return;
        }
        throw new IllegalStateException("layer1 PUT " + path + " returned " + status + ": " + response.body());
    }

    private static Map<String, List<String>> parseRoleMap(String spec) {
        Map<String, List<String>> map = new HashMap<>();
        for (String entry : spec.split(";")) {
            String[] parts = entry.split(":", 2);
            if (parts.length != 2) {
                continue;
            }
            List<String> roles = new ArrayList<>(List.of(parts[1].trim().split("\\s+")));
            map.put(parts[0].trim(), roles);
        }
        return map;
    }

    private record OrgRole(String org, String role, String group) {}
}
