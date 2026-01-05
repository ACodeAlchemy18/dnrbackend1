package com.dnr.erp.modules.quotation.dto;

import java.math.BigDecimal;
import java.util.Date;
import java.util.List;

public class QuotationRequest {
	private String flag = "N";
	private String referenceNo;
    private Date date;
    private Date expirationAt;
    private String companyName;
    private String attention;
    private String designation;
    private String email;
    private String phone;
    private String address;
    private String website;
    private String subject;
    private String project;
    private String title;
    private String currencyCode;
    private String authorName;
    private List<ColumnDto> columns;
    private List<RowDto> rows;
    
    private BigDecimal vat;
    private List<String> scopes;
    
    public QuotationRequest() {}
    
	public String getFlag() {
		return flag;
	}

	public void setFlag(String flag) {
		this.flag = flag;
	}

	public String getReferenceNo() {
		return referenceNo;
	}

	public void setReferenceNo(String referenceNo) {
		this.referenceNo = referenceNo;
	}

	public Date getDate() {
		return date;
	}

	public void setDate(Date date) {
		this.date = date;
	}	

	public Date getExpirationAt() {
		return expirationAt;
	}

	public void setExpirationAt(Date expirationAt) {
		this.expirationAt = expirationAt;
	}

	public String getCompanyName() {
		return companyName;
	}

	public void setCompanyName(String companyName) {
		this.companyName = companyName;
	}

	public String getAttention() {
		return attention;
	}

	public void setAttention(String attention) {
		this.attention = attention;
	}

	public String getDesignation() {
		return designation;
	}

	public void setDesignation(String designation) {
		this.designation = designation;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPhone() {
		return phone;
	}

	public void setPhone(String phone) {
		this.phone = phone;
	}

	public String getAddress() {
		return address;
	}

	public void setAddress(String address) {
		this.address = address;
	}

	public String getWebsite() {
		return website;
	}

	public void setWebsite(String website) {
		this.website = website;
	}

	public String getSubject() {
		return subject;
	}

	public void setSubject(String subject) {
		this.subject = subject;
	}

	public String getProject() {
		return project;
	}

	public void setProject(String project) {
		this.project = project;
	}

	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public String getCurrencyCode() {
		return currencyCode;
	}

	public void setCurrencyCode(String currencyCode) {
		this.currencyCode = currencyCode;
	}

	public String getAuthorName() {
		return authorName;
	}

	public void setAuthorName(String authorName) {
		this.authorName = authorName;
	}

	public List<ColumnDto> getColumns() {
		return columns;
	}

	public void setColumns(List<ColumnDto> columns) {
		this.columns = columns;
	}

	public List<RowDto> getRows() {
		return rows;
	}

	public void setRows(List<RowDto> rows) {
		this.rows = rows;
	}

	public BigDecimal getVat() {
		return vat;
	}

	public void setVat(BigDecimal vat) {
		this.vat = vat;
	}

	public List<String> getScopes() {
		return scopes;
	}

	public void setScopes(List<String> scopes) {
		this.scopes = scopes;
	}
	
		    
}
