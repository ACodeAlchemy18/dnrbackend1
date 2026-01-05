package com.dnr.erp.modules.quotation.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ColumnDto {

    @JsonProperty("id")
    private String id;

    private String columnId;
    private String columnName;

    // NEW metadata
    private Boolean required;   // true/false
    private String inputType;   // "text" | "number" | "calculated"  (maps from JSON "type")
    private String width;       // "120px"
    private String formula;     // e.g. "quantity * unit_rate"

    private String quotationId;

    // getters/setters...
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getColumnId() { return columnId; }
    public void setColumnId(String columnId) { this.columnId = columnId; }

    public String getColumnName() { return columnName; }
    public void setColumnName(String columnName) { this.columnName = columnName; }

    public Boolean getRequired() { return required; }
    public void setRequired(Boolean required) { this.required = required; }

    public String getInputType() { return inputType; }
    public void setInputType(String inputType) { this.inputType = inputType; }

    public String getWidth() { return width; }
    public void setWidth(String width) { this.width = width; }

    public String getFormula() { return formula; }
    public void setFormula(String formula) { this.formula = formula; }

    public String getQuotationId() { return quotationId; }
    public void setQuotationId(String quotationId) { this.quotationId = quotationId; }
}
