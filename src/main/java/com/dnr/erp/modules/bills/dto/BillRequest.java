package com.dnr.erp.modules.bills.dto;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

public class BillRequest {
    private String flag;
    private UUID id;
    private String invoiceNo;
    private LocalDate invoiceDate;
    private String customerName;
    private String customerCompany;
    private String customerAddress;
    private String contactNumber;
    private String customerEmail;
    private BigDecimal subtotal;
    private BigDecimal gstPercent;
    private BigDecimal gstAmount;
    private BigDecimal totalAmount;
    private BigDecimal amountReceived;
    private BigDecimal balanceDue;
    private String paymentMode;
    private String currencyCode;
    private UUID createdBy;
    private List<ItemDto> items;
    
	public String getFlag() {
		return flag;
	}
	public void setFlag(String flag) {
		this.flag = flag;
	}
	public UUID getId() {
		return id;
	}
	public void setId(UUID id) {
		this.id = id;
	}
	public String getInvoiceNo() {
		return invoiceNo;
	}
	public void setInvoiceNo(String invoiceNo) {
		this.invoiceNo = invoiceNo;
	}
	public LocalDate getInvoiceDate() {
		return invoiceDate;
	}
	public void setInvoiceDate(LocalDate invoiceDate) {
		this.invoiceDate = invoiceDate;
	}
	public String getCustomerName() {
		return customerName;
	}
	public void setCustomerName(String customerName) {
		this.customerName = customerName;
	}
	
	public String getCustomerCompany() {
		return customerCompany;
	}
	public void setCustomerCompany(String customerCompany) {
		this.customerCompany = customerCompany;
	}
	public String getCustomerAddress() {
		return customerAddress;
	}
	public void setCustomerAddress(String customerAddress) {
		this.customerAddress = customerAddress;
	}
	public String getContactNumber() {
		return contactNumber;
	}
	public void setContactNumber(String contactNumber) {
		this.contactNumber = contactNumber;
	}
	
	public String getCustomerEmail() {
		return customerEmail;
	}
	public void setCustomerEmail(String customerEmail) {
		this.customerEmail = customerEmail;
	}
	public BigDecimal getSubtotal() {
		return subtotal;
	}
	public void setSubtotal(BigDecimal subtotal) {
		this.subtotal = subtotal;
	}
	public BigDecimal getGstPercent() {
		return gstPercent;
	}
	public void setGstPercent(BigDecimal gstPercent) {
		this.gstPercent = gstPercent;
	}
	public BigDecimal getGstAmount() {
		return gstAmount;
	}
	public void setGstAmount(BigDecimal gstAmount) {
		this.gstAmount = gstAmount;
	}
	public BigDecimal getTotalAmount() {
		return totalAmount;
	}
	public void setTotalAmount(BigDecimal totalAmount) {
		this.totalAmount = totalAmount;
	}
	public BigDecimal getAmountReceived() {
		return amountReceived;
	}
	public void setAmountReceived(BigDecimal amountReceived) {
		this.amountReceived = amountReceived;
	}
	public BigDecimal getBalanceDue() {
		return balanceDue;
	}
	public void setBalanceDue(BigDecimal balanceDue) {
		this.balanceDue = balanceDue;
	}
	public String getPaymentMode() {
		return paymentMode;
	}
	public void setPaymentMode(String paymentMode) {
		this.paymentMode = paymentMode;
	}
	
	public String getCurrencyCode() {
		return currencyCode;
	}
	public void setCurrencyCode(String currencyCode) {
		this.currencyCode = currencyCode;
	}
	public UUID getCreatedBy() {
		return createdBy;
	}
	public void setCreatedBy(UUID createdBy) {
		this.createdBy = createdBy;
	}
	public List<ItemDto> getItems() {
		return items;
	}
	public void setItems(List<ItemDto> items) {
		this.items = items;
	}

    
}

