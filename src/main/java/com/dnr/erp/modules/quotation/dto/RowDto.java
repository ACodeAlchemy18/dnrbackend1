package com.dnr.erp.modules.quotation.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

public class RowDto {

    @JsonProperty("id")
    private String id;

    @JsonProperty("quotation_id")
    private String quotationId;

//    @JsonProperty("row_index")
    private int rowIndex;

    private Map<String, String> cells;

    // Getters and setters
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getQuotationId() {
        return quotationId;
    }

    public void setQuotationId(String quotationId) {
        this.quotationId = quotationId;
    }

    public int getRowIndex() {
        return rowIndex;
    }

    public void setRowIndex(int rowIndex) {
        this.rowIndex = rowIndex;
    }

    public Map<String, String> getCells() {
        return cells;
    }

    public void setCells(Map<String, String> cells) {
        this.cells = cells;
    }
}
