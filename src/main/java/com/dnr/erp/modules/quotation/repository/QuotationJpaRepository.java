package com.dnr.erp.modules.quotation.repository;

import com.dnr.erp.modules.quotation.entity.Quotation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface QuotationJpaRepository extends JpaRepository<Quotation, UUID> {
}