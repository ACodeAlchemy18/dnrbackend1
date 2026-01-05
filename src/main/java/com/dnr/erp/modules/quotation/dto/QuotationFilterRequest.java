package com.dnr.erp.modules.quotation.dto;

import java.util.UUID;

public class QuotationFilterRequest {
    private Integer page = 0;
    private Integer size = 5;
    private String referenceNo;
    private String status;
    private UUID createdBy;
    private UUID quotationId;
    private String authorName;
    
	public Integer getPage() {
		return page;
	}
	public void setPage(Integer page) {
		this.page = page;
	}
	public Integer getSize() {
		return size;
	}
	public void setSize(Integer size) {
		this.size = size;
	}
	public String getReferenceNo() {
		return referenceNo;
	}
	public void setReferenceNo(String referenceNo) {
		this.referenceNo = referenceNo;
	}
	public String getStatus() {
		return status;
	}
	public void setStatus(String status) {
		this.status = status;
	}
	public UUID getCreatedBy() {
		return createdBy;
	}
	public void setCreatedBy(UUID createdBy) {
		this.createdBy = createdBy;
	}
	public UUID getQuotationId() {
		return quotationId;
	}
	public void setQuotationId(UUID quotationId) {
		this.quotationId = quotationId;
	}
	public String getAuthorName() {
		return authorName;
	}
	public void setAuthorName(String authorName) {
		this.authorName = authorName;
	}
	
	
        
}
