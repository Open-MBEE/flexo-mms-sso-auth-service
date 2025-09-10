package org.openmbee.flexo.mms.sso.config;

import org.apache.jena.query.QueryExecution;
import org.apache.jena.query.QuerySolution;
import org.apache.jena.query.ResultSet;
import org.apache.jena.query.QueryFactory;
import org.apache.jena.rdfconnection.RDFConnection;
import org.apache.jena.rdfconnection.RDFConnectionRemote;
import org.apache.jena.update.UpdateProcessor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SparqlConfig {

    @Value("${flexo.sparql.query-url}")
    private String queryUrl;

    @Value("${flexo.sparql.update-url}")
    private String updateUrl;

    @Value("${flexo.sparql.graph-store-protocol-url}")
    private String gspUrl;

    @Value("${flexo.sparql.root-context}")
    private String rootContext;

    public String getQueryUrl() {
        return queryUrl;
    }

    public String getUpdateUrl() {
        return updateUrl;
    }

    public String getGspUrl() {
        return gspUrl;
    }

    public String getRootContext() {
        return rootContext;
    }

    /**
     * Create an RDF connection to the SPARQL endpoint
     * 
     * @return An RDFConnection that can be used for queries and updates
     */
    private RDFConnection createConnection() {
        return RDFConnectionRemote.newBuilder()
            .queryEndpoint(queryUrl)
            .updateEndpoint(updateUrl)
            .gspEndpoint(gspUrl)
            .build();
    }

    /**
     * Execute a SPARQL query against the configured endpoint
     * 
     * @param queryString The SPARQL query to execute
     * @return A QueryExecution that can be used to obtain results
     */
    public QueryExecution createQueryExecution(String queryString) {
        // Create a new connection and get a QueryExecution from it
        RDFConnection connection = createConnection();
        return connection.query(queryString);
    }

    /**
     * Execute a SPARQL update against the configured endpoint
     * 
     * @param updateString The SPARQL update to execute
     */
    public void executeUpdate(String updateString) {
        // Create a new connection and execute the update
        try (RDFConnection connection = createConnection()) {
            connection.update(updateString);
        }
    }
}