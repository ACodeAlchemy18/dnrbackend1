package com.dnr.erp.modules.quotation.entity;

import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "quotations", schema = "dnrcore")
public class Quotation {

    @Id
    @GeneratedValue(generator = "uuid2")
    @Column(columnDefinition = "UUID")
    private UUID id;

    @Column(name = "reference_no")
    private String referenceNo;

    @Column(name = "date")
    private LocalDate date;

    @Column(name = "expiration_at")
    private LocalDate expirationAt;

    @Column(name = "company_name")
    private String companyName;

    @Column(name = "attention")
    private String attention;

    @Column(name = "designation")
    private String designation;

    @Column(name = "email")
    private String email;

    @Column(name = "phone")
    private String phone;

    @Column(name = "address")
    private String address;

    @Column(name = "website")
    private String website;

    @Column(name = "subject")
    private String subject;

    @Column(name = "project")
    private String project;
    
    @Column(name = "title")
    private String title;
    
    @Column(name = "currency_code", length = 3)
    private String currencyCode;
    
    // Optional JSON snapshot or misc data (if you use it)
    @Column(name = "table_data")
    private String tableData;

    @Column(name = "created_by", columnDefinition = "UUID")
    private UUID createdBy;

    @Column(name = "author_name")
    private String authorName;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "status")
    private String status;

    @Column(name = "doc_version")
    private String docVersion;

    // NEW: VAT percentage/value stored for this quotation
    @Column(name = "vat")
    private BigDecimal vat;
    
    @Column(name = "scopes", columnDefinition = "jsonb")
    private String scopes;

    /* ---------- Getters / Setters ---------- */

    public Quotation() {}

    public UUID getId() {
        return id;
    }
    public void setId(UUID id) {
        this.id = id;
    }

    public String getReferenceNo() {
        return referenceNo;
    }
    public void setReferenceNo(String referenceNo) {
        this.referenceNo = referenceNo;
    }

    public LocalDate getDate() {
        return date;
    }
    public void setDate(LocalDate date) {
        this.date = date;
    }

    public LocalDate getExpirationAt() {
        return expirationAt;
    }
    public void setExpirationAt(LocalDate expirationAt) {
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

	public String getTableData() {
        return tableData;
    }
    public void setTableData(String tableData) {
        this.tableData = tableData;
    }

    public UUID getCreatedBy() {
        return createdBy;
    }
    public void setCreatedBy(UUID createdBy) {
        this.createdBy = createdBy;
    }

    public String getAuthorName() {
        return authorName;
    }
    public void setAuthorName(String authorName) {
        this.authorName = authorName;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }
    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public String getStatus() {
        return status;
    }
    public void setStatus(String status) {
        this.status = status;
    }

    public String getDocVersion() {
        return docVersion;
    }
    public void setDocVersion(String docVersion) {
        this.docVersion = docVersion;
    }

    public BigDecimal getVat() {
        return vat;
    }
    public void setVat(BigDecimal vat) {
        this.vat = vat;
    }

	public String getScopes() {
		return scopes;
	}

	public void setScopes(String scopes) {
		this.scopes = scopes;
	}
    
}
