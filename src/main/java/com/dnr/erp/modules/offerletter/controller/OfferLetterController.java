package com.dnr.erp.modules.offerletter.controller;

import com.dnr.erp.modules.offerletter.dto.OfferLetterPdfRequest;
import com.dnr.erp.modules.offerletter.dto.OfferLetterRequest;
import com.dnr.erp.modules.offerletter.service.OfferLetterService;
import com.dnr.erp.modules.quotation.service.PdfService;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/offer-letters")
public class OfferLetterController {

    private final OfferLetterService offerLetterService;
    private final PdfService pdfService;

    public OfferLetterController(OfferLetterService offerLetterService, PdfService pdfService) {
        this.offerLetterService = offerLetterService;
        this.pdfService = pdfService;
    }

    @PostMapping("/save")
    public ResponseEntity<?> saveOfferLetter(@RequestBody OfferLetterRequest request) {
        try {
            Map<String, Object> result = offerLetterService.createOfferLetter(request);
            if ("F".equals(String.valueOf(result.get("resultStatus")))) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(result);
            }
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    // ✅ Single flexible endpoint: by id OR paginated with filters
    @PostMapping("/get")
    public ResponseEntity<?> getOfferLetters(@RequestBody Map<String, Object> body) {
        try {
            UUID id        = body.get("offerLetterId") != null ? UUID.fromString(body.get("offerLetterId").toString()) : null;
            UUID createdBy = body.get("createdBy")     != null ? UUID.fromString(body.get("createdBy").toString())     : null;
            String status  = body.get("status")        != null ? body.get("status").toString()                         : null;
            Integer page   = body.get("page")          != null ? Integer.valueOf(body.get("page").toString())          : 0;
            Integer size   = body.get("size")          != null ? Integer.valueOf(body.get("size").toString())          : 10;
            String search  = body.get("search")        != null ? body.get("search").toString()                         : null;

            JsonNode result = offerLetterService.fetchOfferLetters(id, createdBy, status, page, size, search);
            String rs = result.has("resultStatus") ? result.get("resultStatus").asText() : "S";
            if ("F".equals(rs)) return ResponseEntity.status(HttpStatus.NOT_FOUND).body(result);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/generate")
    public ResponseEntity<byte[]> generateHtmlPdf(@RequestBody OfferLetterPdfRequest payload) throws IOException {
        String html = payload.getHtml();
        if (html == null || html.isBlank()) return ResponseEntity.badRequest().body(null);

        byte[] pdfBytes = pdfService.generateHtmlToPdf(html);
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.inline()
                                .filename("offer-letter.pdf")
                                .build()
                                .toString())
                .body(pdfBytes);
    }
}
