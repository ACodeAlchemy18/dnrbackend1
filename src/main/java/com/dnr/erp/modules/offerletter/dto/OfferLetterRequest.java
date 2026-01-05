package com.dnr.erp.modules.offerletter.dto;

import java.util.Date;
import java.util.List;
import java.util.UUID;

public class OfferLetterRequest {
	private UUID offerLetterId;
    private String employeeName;
    private String position;
    private String salary;
    private Date joiningDate;
    private List<SalaryBreakdownItem> salaryBreakdown;
    private UUID createdBy;
    
    private String nationality;
    private String currencyCode;

    public static class SalaryBreakdownItem {
        private String label;
        private double amount;

        public String getLabel() {
            return label;
        }

        public void setLabel(String label) {
            this.label = label;
        }

        public double getAmount() {
            return amount;
        }

        public void setAmount(double amount) {
            this.amount = amount;
        }
    }

    public UUID getOfferLetterId() {
		return offerLetterId;
	}
	public void setOfferLetterId(UUID offerLetterId) {
		this.offerLetterId = offerLetterId;
	}
	// Getters and setters...
    public String getEmployeeName() {
        return employeeName;
    }
    public void setEmployeeName(String employeeName) {
        this.employeeName = employeeName;
    }
    public String getPosition() {
        return position;
    }
    public void setPosition(String position) {
        this.position = position;
    }
    public String getSalary() {
        return salary;
    }
    public void setSalary(String salary) {
        this.salary = salary;
    }
    public Date getJoiningDate() {
        return joiningDate;
    }
    public void setJoiningDate(Date joiningDate) {
        this.joiningDate = joiningDate;
    }
    public List<SalaryBreakdownItem> getSalaryBreakdown() {
        return salaryBreakdown;
    }
    public void setSalaryBreakdown(List<SalaryBreakdownItem> salaryBreakdown) {
        this.salaryBreakdown = salaryBreakdown;
    }
    public UUID getCreatedBy() {
        return createdBy;
    }
    public void setCreatedBy(UUID createdBy) {
        this.createdBy = createdBy;
    }
    public String getNationality() { return nationality; }
    public void setNationality(String nationality) { this.nationality = nationality; }
	public String getCurrencyCode() {
		return currencyCode;
	}
	public void setCurrencyCode(String currencyCode) {
		this.currencyCode = currencyCode;
	}
    
}
