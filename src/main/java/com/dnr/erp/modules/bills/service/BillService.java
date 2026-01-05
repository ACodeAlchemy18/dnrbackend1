package com.dnr.erp.modules.bills.service;

import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.Date;
import java.sql.Types;
import java.util.UUID;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.dnr.erp.modules.bills.dto.BillRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@Service
public class BillService {

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public BillService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    private UUID getLoggedInUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated()) {
            // If your JWT subject ("sub") is the UUID, Spring uses it as Authentication#getName()
            return UUID.fromString(auth.getName());
        }
        throw new RuntimeException("Unauthorized: cannot extract user id from token");
    }

    public JsonNode saveOrUpdateBill(BillRequest request) {
        return jdbcTemplate.execute((Connection con) -> {
            try {
                CallableStatement cs = con.prepareCall("{ call dnrcore.prr_add_bill_details(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) }");

                cs.setString(1, request.getFlag());
                cs.setObject(2, request.getId());
                cs.setString(3, null);
                cs.setDate(4, Date.valueOf(request.getInvoiceDate()));
                cs.setString(5, request.getCustomerName());
                cs.setString(6, request.getCustomerCompany());
                cs.setString(7, request.getCustomerAddress());
                cs.setString(8, request.getContactNumber());
                cs.setString(9, request.getCustomerEmail());
                cs.setBigDecimal(10, request.getSubtotal());
                cs.setBigDecimal(11, request.getGstPercent());
                cs.setBigDecimal(12, request.getGstAmount());
                cs.setBigDecimal(13, request.getTotalAmount());
                cs.setBigDecimal(14, request.getAmountReceived());
                cs.setBigDecimal(15, request.getBalanceDue());
                cs.setString(16, request.getPaymentMode());
                cs.setString(17, request.getCurrencyCode());
                cs.setObject(18, getLoggedInUserId()); // p_i_created_by

                // items JSONB
                cs.setObject(19, objectMapper.writeValueAsString(request.getItems()), Types.OTHER); // p_i_items

                cs.registerOutParameter(20, Types.OTHER); // p_json_result

                cs.execute();

                Object result = cs.getObject(20);
                return objectMapper.readTree(result.toString());

            } catch (Exception e) {
                e.printStackTrace();
                return objectMapper.createObjectNode().put("error", "Bill creation failed: " + e.getMessage());
            }
        });
    }

    public JsonNode getBillsFlexible(UUID billId, UUID createdBy, Integer page, Integer size) {
        return jdbcTemplate.execute((Connection con) -> {
            try (CallableStatement cs = con.prepareCall(
                    "{ call dnrcore.prr_call_get_bill_details(?, ?, ?, ?, ?) }"
            )) {
                if (billId != null) cs.setObject(1, billId); else cs.setNull(1, Types.OTHER);
                if (createdBy != null) cs.setObject(2, createdBy); else cs.setNull(2, Types.OTHER);
                if (page != null) cs.setInt(3, page); else cs.setNull(3, Types.INTEGER);
                if (size != null) cs.setInt(4, size); else cs.setNull(4, Types.INTEGER);

                cs.registerOutParameter(5, Types.OTHER); // p_json_result
                cs.execute();

                Object result = cs.getObject(5);
                return objectMapper.readTree(result.toString());

            } catch (Exception e) {
                e.printStackTrace();
                return objectMapper.createObjectNode().put("error", "Bill fetch failed: " + e.getMessage());
            }
        });
    }
}