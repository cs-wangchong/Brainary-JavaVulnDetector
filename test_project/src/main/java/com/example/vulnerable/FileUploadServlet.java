package com.example.vulnerable;

import javax.servlet.http.*;
import java.io.*;
import org.apache.commons.fileupload.*;
import org.apache.commons.fileupload.servlet.*;
import org.apache.commons.fileupload.disk.*;
import java.util.*;

/**
 * FileUploadServlet with path traversal and unrestricted file upload vulnerabilities
 * CWE-22: Path Traversal
 * CWE-434: Unrestricted Upload of File with Dangerous Type
 */
public class FileUploadServlet extends HttpServlet {
    
    private static final String UPLOAD_DIR = "/uploads/";
    
    /**
     * Vulnerable file upload with no validation
     */
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws IOException {
        
        try {
            // Path traversal vulnerability - using user-provided filename directly
            String filename = request.getParameter("filename");
            
            // No file type validation - can upload any file including .jsp, .war
            File uploadFile = new File(UPLOAD_DIR + filename);
            
            // Create parent directories if they don't exist
            uploadFile.getParentFile().mkdirs();
            
            // Write file content
            InputStream fileContent = request.getInputStream();
            OutputStream outputStream = new FileOutputStream(uploadFile);
            
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fileContent.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
            
            outputStream.close();
            fileContent.close();
            
            // XSS vulnerability in response
            response.getWriter().write("<html><body>");
            response.getWriter().write("File uploaded successfully: " + filename);
            response.getWriter().write("</body></html>");
            
        } catch (Exception e) {
            response.getWriter().write("Upload failed: " + e.getMessage());
        }
    }
    
    /**
     * Download file with path traversal vulnerability
     */
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws IOException {
        
        String filename = request.getParameter("file");
        
        // Path traversal - allows accessing files outside upload directory
        // e.g., file=../../../etc/passwd
        File file = new File(UPLOAD_DIR + filename);
        
        if (file.exists()) {
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
            
            FileInputStream fileIn = new FileInputStream(file);
            OutputStream out = response.getOutputStream();
            
            byte[] buffer = new byte[4096];
            int length;
            while ((length = fileIn.read(buffer)) > 0) {
                out.write(buffer, 0, length);
            }
            
            fileIn.close();
            out.close();
        } else {
            response.getWriter().write("File not found: " + filename);
        }
    }
}
