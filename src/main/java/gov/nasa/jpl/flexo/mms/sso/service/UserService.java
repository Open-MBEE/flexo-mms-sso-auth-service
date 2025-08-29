package org.openmbee.flexo.mms.sso.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class UserService {

    public Map<String, Object> getUserDetails(Authentication authentication) {
        Map<String, Object> userDetails = new HashMap<>();
        
        if (authentication.getPrincipal() instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
            userDetails.put("id", oidcUser.getName());
            userDetails.put("name", oidcUser.getFullName());
            userDetails.put("username", oidcUser.getPreferredUsername());
            userDetails.put("email", oidcUser.getEmail());
            userDetails.put("claims", oidcUser.getClaims());
            userDetails.put("idToken", oidcUser.getIdToken().getTokenValue());
        }
        
        return userDetails;
    }

    public void checkMmsUserGroups() {
        String rootContext = environment.getConfig().property("ldap.groupStore.context").getString();
        String storeUri = environment.getConfig().property("ldap.groupStore.uri").getString();
        String sparql =
                "prefix mms: <https://mms.openmbee.org/rdf/ontology/>\n" +
                        "base <" + rootContext + ">\n" +
                        "prefix m: <>\n" +
                        "prefix m-graph: <graphs/>\n" +
                        "select ?groupId from m-graph:AccessControl.Agents {\n" +
                        "    ?group a mms:Group ;\n" +
                        "    mms:id ?groupId ;\n" +
                        "    .\n" +
                        "}";

    }
}
