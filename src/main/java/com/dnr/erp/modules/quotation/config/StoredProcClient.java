package com.dnr.erp.modules.quotation.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.SqlOutParameter;
import org.springframework.jdbc.core.SqlParameter;
import org.springframework.jdbc.core.simple.SimpleJdbcCall;
import org.springframework.stereotype.Component;

import java.sql.Types;
import java.util.Map;
import java.util.UUID;

@Component
public class StoredProcClient {

    private static final Logger logger = LoggerFactory.getLogger(StoredProcClient.class);

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public StoredProcClient(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    /**
     * For stored procedures with pagination filters.
     */
    public JsonNode callPaginatedProc(String procName, Map<String, Object> inputParams) {
        logger.debug("Calling paginated stored procedure: {} with parameters: {}", procName, inputParams);

        try {
            SimpleJdbcCall call = new SimpleJdbcCall(jdbcTemplate)
                    .withSchemaName("dnrcore")
                    .withProcedureName(procName)
                    .withoutProcedureColumnMetaDataAccess()
                    .declareParameters(
                        new SqlOutParameter("p_json_result", Types.OTHER),
                        new SqlParameter("p_i_page", Types.INTEGER),
                        new SqlParameter("p_i_size", Types.INTEGER),
                        new SqlParameter("p_i_reference_no", Types.VARCHAR),
                        new SqlParameter("p_i_status", Types.VARCHAR),
                        new SqlParameter("p_i_created_by", Types.OTHER), // UUID
                        new SqlParameter("p_i_author_name", Types.VARCHAR),
                        new SqlParameter("p_i_quotation_id", Types.OTHER) // UUID
                    );

            Map<String, Object> result = call.execute(inputParams);
            return getJsonResult(procName, result);

        } catch (Exception ex) {
            logger.error("Error in paginated procedure call: {}", procName, ex);
            throw new RuntimeException("Failed to call stored procedure: " + procName, ex);
        }
    }

    /**
     * For prr_create_quotation stored procedure.
     */
    public JsonNode callCreateQuotationProc(String procName, Map<String, Object> inputParams) {
        logger.debug("Calling create quotation procedure: {} with parameters: {}", procName, inputParams);
        
        try {
            SimpleJdbcCall call = new SimpleJdbcCall(jdbcTemplate)
                    .withSchemaName("dnrcore")
                    .withProcedureName(procName)
                    .withoutProcedureColumnMetaDataAccess()
                    .declareParameters(
                        
                        
                        // Input parameters with explicit types
                    	new SqlParameter("p_i_flag", Types.VARCHAR),
                        new SqlParameter("p_i_reference_no", Types.VARCHAR),
                        new SqlParameter("p_i_date", Types.DATE),
                        new SqlParameter("p_i_expiration_at", Types.DATE),
                        new SqlParameter("p_i_company_name", Types.VARCHAR),
                        new SqlParameter("p_i_attention", Types.VARCHAR),
                        new SqlParameter("p_i_designation", Types.VARCHAR),
                        new SqlParameter("p_i_email", Types.VARCHAR),
                        new SqlParameter("p_i_phone", Types.VARCHAR),
                        new SqlParameter("p_i_address", Types.VARCHAR),
                        new SqlParameter("p_i_website", Types.VARCHAR),
                        new SqlParameter("p_i_subject", Types.VARCHAR),
                        new SqlParameter("p_i_project", Types.VARCHAR),
                        
                        new SqlParameter("p_i_title", Types.VARCHAR),
                        
                        new SqlParameter("p_i_currency_code", Types.VARCHAR),
                        
                        new SqlParameter("p_i_vat", Types.NUMERIC),
                        // JSON parameters as TEXT
                        new SqlParameter("p_i_columns", Types.VARCHAR),
                        new SqlParameter("p_i_rows", Types.VARCHAR),
                        
                        // UUID parameter
                        new SqlParameter("p_i_created_by", Types.OTHER),
                        new SqlParameter("p_i_author_name", Types.VARCHAR),
                        new SqlParameter("p_i_scopes", Types.VARCHAR),
                        new SqlOutParameter("p_json_result", Types.OTHER)
                    );

            Map<String, Object> result = call.execute(inputParams);
            return getJsonResult(procName, result);

        } catch (Exception ex) {
            logger.error("Error in createQuotation procedure call: {}", procName, ex);
            throw new RuntimeException("Failed to call stored procedure: " + procName, ex);
        }
    }
    
    public JsonNode callGetQuotationWithDetails(String procName, UUID quotationId) {
        try {
            SimpleJdbcCall call = new SimpleJdbcCall(jdbcTemplate)
                    .withSchemaName("dnrcore")
                    .withProcedureName(procName)
                    .withoutProcedureColumnMetaDataAccess()
                    .declareParameters(
                            new SqlParameter("p_i_quotation_id", Types.OTHER), // UUID
                            new SqlOutParameter("p_json_result", Types.OTHER)
                    );

            Map<String, Object> inParams = Map.of("p_i_quotation_id", quotationId);
            Map<String, Object> result = call.execute(inParams);
            return getJsonResult(procName, result);
        } catch (Exception ex) {
            logger.error("Error in callGetQuotationWithDetails: {}", procName, ex);
            throw new RuntimeException("Failed to fetch quotation details for PDF", ex);
        }
    }


    /**
     * Extracts JSON result from the procedure call.
     */
    private JsonNode getJsonResult(String procName, Map<String, Object> result) throws Exception {
        Object jsonResult = result.get("p_json_result");

        if (jsonResult == null) {
            logger.warn("Stored procedure {} returned null", procName);
            return objectMapper.readTree("{\"resultStatus\":\"F\", \"resultMessage\":\"Null response from stored procedure\"}");
        }

        logger.debug("Stored procedure {} returned: {}", procName, jsonResult);
        return objectMapper.readTree(jsonResult.toString());
    }
}
