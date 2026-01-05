package com.dnr.erp.modules.quotation.repository;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.StoredProcedureQuery;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public class QuotationRepository {

    @PersistenceContext
    private EntityManager entityManager;

    public ResponseEntity<?> callGetQuotationsProcedure(int page, int size, String referenceNo, String status, UUID createdBy, UUID quotationId) {
        StoredProcedureQuery query = entityManager.createStoredProcedureQuery("dnrcore.prr_get_paginated_quotations");
        query.registerStoredProcedureParameter("p_json_result", String.class, jakarta.persistence.ParameterMode.OUT);
        query.registerStoredProcedureParameter("p_i_page", Integer.class, jakarta.persistence.ParameterMode.IN);
        query.registerStoredProcedureParameter("p_i_size", Integer.class, jakarta.persistence.ParameterMode.IN);
        query.registerStoredProcedureParameter("p_i_reference_no", String.class, jakarta.persistence.ParameterMode.IN);
        query.registerStoredProcedureParameter("p_i_status", String.class, jakarta.persistence.ParameterMode.IN);
        query.registerStoredProcedureParameter("p_i_created_by", UUID.class, jakarta.persistence.ParameterMode.IN);
        query.registerStoredProcedureParameter("p_i_quotation_id", UUID.class, jakarta.persistence.ParameterMode.IN);

        query.setParameter("p_i_page", page);
        query.setParameter("p_i_size", size);
        query.setParameter("p_i_reference_no", referenceNo);
        query.setParameter("p_i_status", status);
        query.setParameter("p_i_created_by", createdBy);
        query.setParameter("p_i_quotation_id", quotationId);

        query.execute();
        String jsonResult = (String) query.getOutputParameterValue("p_json_result");
        return ResponseEntity.ok().body(jsonResult);
    }
    
    public ResponseEntity<?> callCreateQuotationProcedure(
            String referenceNo,
            java.sql.Date date,
            java.sql.Date expirationAt,
            String companyName,
            String attention,
            String designation,
            String email,
            String phone,
            String address,
            String website,
            String subject,
            String project,
            String title,
            String currencyCode,
            String columnsJson,
            String rowsJson,
            UUID createdBy,
            String authorName,
            String scopesJson
    ) {
        StoredProcedureQuery query = entityManager.createStoredProcedureQuery("dnrcore.prr_create_quotation");

        query.registerStoredProcedureParameter("p_i_date", java.sql.Date.class, jakarta.persistence.ParameterMode.IN);
        query.registerStoredProcedureParameter("p_i_expiration_at", java.sql.Date.class, jakarta.persistence.ParameterMode.IN); // NEW
        query.registerStoredProcedureParameter("p_i_company_name", String.class, jakarta.persistence.ParameterMode.IN);
        query.registerStoredProcedureParameter("p_i_attention", String.class, jakarta.persistence.ParameterMode.IN);
        query.registerStoredProcedureParameter("p_i_designation", String.class, jakarta.persistence.ParameterMode.IN);
        query.registerStoredProcedureParameter("p_i_email", String.class, jakarta.persistence.ParameterMode.IN);
        query.registerStoredProcedureParameter("p_i_phone", String.class, jakarta.persistence.ParameterMode.IN);
        query.registerStoredProcedureParameter("p_i_address", String.class, jakarta.persistence.ParameterMode.IN);
        query.registerStoredProcedureParameter("p_i_website", String.class, jakarta.persistence.ParameterMode.IN);
        query.registerStoredProcedureParameter("p_i_subject", String.class, jakarta.persistence.ParameterMode.IN);
        query.registerStoredProcedureParameter("p_i_project", String.class, jakarta.persistence.ParameterMode.IN);
        query.registerStoredProcedureParameter("p_i_title", String.class, jakarta.persistence.ParameterMode.IN);
        query.registerStoredProcedureParameter("p_i_currency_code", String.class, jakarta.persistence.ParameterMode.IN);
        query.registerStoredProcedureParameter("p_i_columns", String.class, jakarta.persistence.ParameterMode.IN); // VARCHAR not CLOB
        query.registerStoredProcedureParameter("p_i_rows", String.class, jakarta.persistence.ParameterMode.IN);    // VARCHAR not CLOB
        query.registerStoredProcedureParameter("p_i_created_by", UUID.class, jakarta.persistence.ParameterMode.IN);
        query.registerStoredProcedureParameter("p_i_author_name", String.class, jakarta.persistence.ParameterMode.IN); // NEW
        query.registerStoredProcedureParameter("p_i_scopes", String.class, jakarta.persistence.ParameterMode.IN);
        query.registerStoredProcedureParameter("p_json_result", String.class, jakarta.persistence.ParameterMode.OUT);

        query.setParameter("p_i_date", date);
        query.setParameter("p_i_expiration_at", expirationAt);
        query.setParameter("p_i_company_name", companyName);
        query.setParameter("p_i_attention", attention);
        query.setParameter("p_i_designation", designation);
        query.setParameter("p_i_email", email);
        query.setParameter("p_i_phone", phone);
        query.setParameter("p_i_address", address);
        query.setParameter("p_i_website", website);
        query.setParameter("p_i_subject", subject);
        query.setParameter("p_i_project", project);
        query.setParameter("p_i_title", title);
        query.setParameter("p_i_currency_code", currencyCode);
        query.setParameter("p_i_columns", columnsJson);
        query.setParameter("p_i_rows", rowsJson);
        query.setParameter("p_i_created_by", createdBy);
        query.setParameter("p_i_author_name", authorName);
        query.setParameter("p_i_scopes", scopesJson);

        query.execute();
        String jsonResult = (String) query.getOutputParameterValue("p_json_result");
        return ResponseEntity.ok().body(jsonResult);
    }

}
