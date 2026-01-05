package com.dnr.erp.modules.quotation.service;

import com.itextpdf.io.source.ByteArrayOutputStream;
import com.lowagie.text.DocumentException;
import org.springframework.stereotype.Service;
import org.xhtmlrenderer.pdf.ITextRenderer;

import java.io.File;
import java.io.IOException;
import java.net.URL;

@Service
public class PdfService {

    public byte[] generateHtmlToPdf(String htmlContent) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            ITextRenderer renderer = new ITextRenderer();

            // Safer way to load images from /static folder inside resources
            URL baseResource = getClass().getResource("/static/");
            String baseUrl = baseResource != null ? baseResource.toString() : new File("src/main/resources/static").toURI().toString();

            renderer.getSharedContext().setPrint(true);
            renderer.getSharedContext().setInteractive(false);
            renderer.getSharedContext().setBaseURL(baseUrl);

            renderer.setDocumentFromString(htmlContent, baseUrl);
            renderer.layout();
            renderer.createPDF(baos);

            return baos.toByteArray();
        } catch (IOException | DocumentException e) {
            throw new RuntimeException("Failed to generate PDF from HTML", e);
        }
    }
}
