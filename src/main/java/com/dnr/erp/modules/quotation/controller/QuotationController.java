package com.dnr.erp.modules.quotation.controller;

import com.dnr.erp.modules.quotation.dto.QuotationFilterRequest;
import com.dnr.erp.modules.quotation.dto.QuotationRequest;
import com.dnr.erp.modules.quotation.service.PdfService;
import com.dnr.erp.modules.quotation.service.QuotationService;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/quotations")
@CrossOrigin(origins = "${frontend.origin}", allowCredentials = "true")
public class QuotationController {

	@Autowired
    private QuotationService service;
	
	@Autowired
	private PdfService pdfService;

    public QuotationController(QuotationService service) {
        this.service = service;
    }
    
    @PreAuthorize("hasAnyRole('ADMIN', 'USER')")
    @PostMapping("/create")
    public ResponseEntity<JsonNode> createQuotation(@RequestBody QuotationRequest request) {
        JsonNode result = service.createQuotation(request);
        return ResponseEntity.ok(result);
    }
    
    @PreAuthorize("hasAnyRole('ADMIN', 'USER')")
    @PostMapping("/edit")
    public ResponseEntity<JsonNode> editQuotation(@RequestBody QuotationRequest request) {
        request.setFlag("E");
        JsonNode result = service.createQuotation(request);
        return ResponseEntity.ok(result);
    }

    // 1. Get paginated quotations (no filters required)
    @PostMapping("/paginated")
    public ResponseEntity<JsonNode> getPaginated(@RequestBody QuotationFilterRequest request) {
        return ResponseEntity.ok(service.getQuotations(request));
    }

    // 2. Get full quotation by quotationId
    @PostMapping("/by-id")
    public ResponseEntity<JsonNode> getById(@RequestBody QuotationFilterRequest request) {
        return ResponseEntity.ok(service.getQuotations(request));
    }

    // 3. Get quotations by createdBy user (with pagination)
    @PostMapping("/by-user")
    public ResponseEntity<JsonNode> getByUser(@RequestBody QuotationFilterRequest request) {
        return ResponseEntity.ok(service.getQuotations(request));
    }
    
    @PostMapping("/generate-html-pdf")
    public ResponseEntity<byte[]> generateHtmlPdf(@RequestBody Map<String, String> payload) throws IOException {
        String html = payload.get("html");

        if (html == null || html.isBlank()) {
            return ResponseEntity.badRequest().body(null);
        }

        byte[] pdfBytes = pdfService.generateHtmlToPdf(html); // 🔄 use PdfService here

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.inline()
                                .filename("quotation.pdf")
                                .build()
                                .toString())
                .body(pdfBytes);
    }



}
