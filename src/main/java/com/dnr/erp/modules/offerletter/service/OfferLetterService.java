package com.dnr.erp.modules.offerletter.service;

import com.dnr.erp.modules.offerletter.dto.OfferLetterRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.jdbc.core.SqlOutParameter;
import org.springframework.jdbc.core.SqlParameter;
import org.springframework.jdbc.core.simple.SimpleJdbcCall;
import org.springframework.stereotype.Service;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.Authentication;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;


import javax.sql.DataSource;
import java.sql.Types;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class OfferLetterService {

    private final SimpleJdbcCall createOfferProc;
    private final SimpleJdbcCall getOfferProc; // ✅ New field
    private final ObjectMapper objectMapper;
    
    private UUID getLoggedInUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated()) {
            return UUID.fromString(auth.getName());
        }
        throw new RuntimeException("Unauthorized: Cannot extract user ID");
    }

    public OfferLetterService(DataSource dataSource, ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;

        // ✅ Procedure to create offer letter
        this.createOfferProc = new SimpleJdbcCall(dataSource)
                .withSchemaName("dnrcore")
                .withProcedureName("prr_create_offer_letter")
                .withoutProcedureColumnMetaDataAccess()
                .declareParameters(
                        new SqlParameter("p_i_flag", Types.CHAR),
                        new SqlParameter("p_i_offer_letter_id", Types.OTHER), // UUID
                        new SqlParameter("p_i_candidate_name", Types.VARCHAR),
                        new SqlParameter("p_i_position", Types.VARCHAR),
                        new SqlParameter("p_i_nationality", Types.VARCHAR),
                        new SqlParameter("p_i_currency_code", Types.VARCHAR),
                        new SqlParameter("p_i_ctc", Types.VARCHAR),
                        new SqlParameter("p_i_joining_date", Types.DATE),
                        new SqlParameter("p_i_salary_breakdown", Types.OTHER), // JSONB
                        new SqlParameter("p_i_created_by", Types.OTHER),
                        new SqlOutParameter("p_json_result", Types.OTHER)
                );

        // ✅ Procedure to fetch offer letter
        this.getOfferProc = new SimpleJdbcCall(dataSource)
                .withSchemaName("dnrcore")
                .withProcedureName("prr_call_get_offer_letter")
                .withoutProcedureColumnMetaDataAccess()
                .declareParameters(
                		new SqlOutParameter("p_json_result", Types.OTHER),
                        new SqlParameter("p_i_offer_letter_id", Types.OTHER),
                        new SqlParameter("p_i_created_by", Types.OTHER),
                        new SqlParameter("p_i_status", Types.VARCHAR),
                        new SqlParameter("p_i_page", Types.INTEGER),
                        new SqlParameter("p_i_size", Types.INTEGER),
                        new SqlParameter("p_i_search", Types.VARCHAR)
                );
    }

    public Map<String, Object> createOfferLetter(OfferLetterRequest request) {
        try {
            Map<String, Object> inParams = new HashMap<>();
            inParams.put("p_i_flag", request.getOfferLetterId() == null ? "N" : "U");
            inParams.put("p_i_offer_letter_id", request.getOfferLetterId());
            inParams.put("p_i_candidate_name", request.getEmployeeName());
            inParams.put("p_i_position", request.getPosition());
            inParams.put("p_i_nationality", request.getNationality() == null ? null : request.getNationality().trim());
            inParams.put("p_i_currency_code", request.getCurrencyCode());
            inParams.put("p_i_ctc", request.getSalary());
            inParams.put("p_i_joining_date", new java.sql.Date(request.getJoiningDate().getTime()));
            inParams.put("p_i_salary_breakdown", objectMapper.writeValueAsString(request.getSalaryBreakdown()));
            inParams.put("p_i_created_by", getLoggedInUserId());

            Map<String, Object> result = createOfferProc.execute(inParams);
            Object jsonResult = result.get("p_json_result");

            return objectMapper.readValue(jsonResult.toString(), Map.class);

        } catch (DataIntegrityViolationException ex) {
            if (ex.getMostSpecificCause().getMessage().contains("uq_offer_letter_candidate")) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Offer letter already exists for this candidate");
            }
            throw ex; // rethrow other integrity issues
        } catch (Exception e) {
            throw new RuntimeException("Failed to call prr_create_offer_letter: " + e.getMessage(), e);
        }
    }

    public JsonNode getOfferLetterById(UUID offerLetterId, UUID createdBy) {
        return fetchOfferLetters(offerLetterId, createdBy, null, null, null, null);
    }

    /** Flexible fetch: single-by-id OR paginated list with optional filters */
    public JsonNode fetchOfferLetters(UUID offerLetterId,
                                      UUID createdBy,
                                      String status,
                                      Integer page,
                                      Integer size,
                                      String search) {
        try {
            Map<String, Object> in = new HashMap<>();
            in.put("p_i_offer_letter_id", offerLetterId);
            in.put("p_i_created_by", createdBy);
            in.put("p_i_status", status);
            in.put("p_i_page", page);
            in.put("p_i_size", size);
            in.put("p_i_search", search);

            Map<String, Object> out = getOfferProc.execute(in);
            Object json = out.get("p_json_result");
            return objectMapper.readTree(json.toString());
        } catch (Exception e) {
            throw new RuntimeException("Failed to call prr_call_get_offer_letter: " + e.getMessage(), e);
        }
    }
}