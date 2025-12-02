package com.example.vulnerable;

import javax.servlet.http.*;
import java.io.*;

/**
 * SessionManager with authentication and session management vulnerabilities
 * CWE-306: Missing Authentication
 * CWE-614: Sensitive Cookie Without 'HttpOnly' Flag
 * CWE-311: Missing Encryption of Sensitive Data
 */
public class SessionManager extends HttpServlet {
    
    /**
     * Create session without proper security flags
     */
    public void doLogin(HttpServletRequest request, HttpServletResponse response) 
            throws IOException {
        
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        // Weak authentication - no password hashing comparison
        if (username != null && password != null) {
            HttpSession session = request.getSession(true);
            session.setAttribute("username", username);
            session.setAttribute("password", password); // Storing password in session!
            
            // Set insecure cookie without HttpOnly and Secure flags
            Cookie cookie = new Cookie("sessionId", session.getId());
            cookie.setMaxAge(3600);
            // Missing: cookie.setHttpOnly(true);
            // Missing: cookie.setSecure(true);
            response.addCookie(cookie);
            
            // Store sensitive data in cookie
            Cookie userCookie = new Cookie("userdata", username + ":" + password);
            response.addCookie(userCookie);
            
            response.getWriter().write("Login successful");
        }
    }
    
    /**
     * Access sensitive operation without authentication check
     */
    public void deleteUser(HttpServletRequest request, HttpServletResponse response) 
            throws IOException {
        
        // Missing authentication/authorization check
        String userId = request.getParameter("userId");
        
        // Directly delete user without verifying permissions
        response.getWriter().write("User " + userId + " deleted");
    }
    
    /**
     * Change password without verifying current password
     */
    public void changePassword(HttpServletRequest request, HttpServletResponse response) 
            throws IOException {
        
        HttpSession session = request.getSession(false);
        String newPassword = request.getParameter("newPassword");
        
        // No verification of current password
        // No password strength check
        if (session != null) {
            session.setAttribute("password", newPassword);
            response.getWriter().write("Password changed");
        }
    }
    
    /**
     * Access control bypass - missing authorization
     */
    public void viewAdminPanel(HttpServletRequest request, HttpServletResponse response) 
            throws IOException {
        
        // No role/permission check
        response.getWriter().write("<html><body>");
        response.getWriter().write("<h1>Admin Panel</h1>");
        response.getWriter().write("<p>Sensitive admin data...</p>");
        response.getWriter().write("</body></html>");
    }
    
    /**
     * Session fixation vulnerability
     */
    public void processLogin(HttpServletRequest request, HttpServletResponse response) 
            throws IOException {
        
        String username = request.getParameter("username");
        
        // Reusing existing session instead of creating new one
        HttpSession session = request.getSession(false);
        if (session != null) {
            // Should invalidate old session and create new one
            session.setAttribute("authenticated", true);
            session.setAttribute("user", username);
        }
    }
}
