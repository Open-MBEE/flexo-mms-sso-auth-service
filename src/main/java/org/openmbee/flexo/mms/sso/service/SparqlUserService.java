package org.openmbee.flexo.mms.sso.service;

import org.apache.jena.query.QueryExecution;
import org.apache.jena.query.QuerySolution;
import org.apache.jena.query.ResultSet;
import org.apache.jena.rdf.model.RDFNode;
import org.openmbee.flexo.mms.sso.config.SparqlConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class SparqlUserService {

    private final SparqlConfig sparqlConfig;

    @Autowired
    public SparqlUserService(SparqlConfig sparqlConfig) {
        this.sparqlConfig = sparqlConfig;
    }

    /**
     * Get all available groups from the SPARQL database
     * 
     * @param username The username parameter is kept for compatibility but not used
     * @return A list of group identifiers
     */
    public List<String> getUserGroups(String username) {
        String queryString = buildGroupsQuery();
        List<String> groups = new ArrayList<>();
        
        try (QueryExecution qexec = sparqlConfig.createQueryExecution(queryString)) {
            ResultSet results = qexec.execSelect();
            
            while (results.hasNext()) {
                QuerySolution soln = results.nextSolution();
                RDFNode groupId = soln.get("groupId");
                if (groupId != null && groupId.isLiteral()) {
                    groups.add(groupId.asLiteral().getString());
                }
            }
            
            return groups;
        } catch (Exception e) {
            System.err.println("Error retrieving groups from SPARQL database: " + e.getMessage());
            return List.of();
        }
    }

    /**
     * Build a SPARQL query to get all available groups
     */
    private String buildGroupsQuery() {
        String rootContext = sparqlConfig.getRootContext();
        
        return "PREFIX mms: <https://mms.openmbee.org/rdf/ontology/>\n" +
               "BASE <" + rootContext + ">\n" +
               "PREFIX m: <>\n" +
               "PREFIX m-graph: <graphs/>\n" +
               "SELECT ?groupId FROM m-graph:AccessControl.Agents {\n" +
               "    ?group a mms:Group ;\n" +
               "           mms:id ?groupId .\n" +
               "}";
    }
}