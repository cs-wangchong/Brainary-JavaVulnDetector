package com.example.vulnerable;

import java.sql.*;
import javax.servlet.http.*;
import java.io.*;

/**
 * UserController with SQL Injection vulnerabilities
 * CWE-89: SQL Injection
 */
public class UserController extends HttpServlet {
    
    private static final String DB_URL = "jdbc:mysql://localhost:3306/mydb";
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "P@ssw0rd123"; // CWE-798: Hardcoded credentials
    
    /**
     * Vulnerable login method with SQL injection
     */
    public void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws IOException {
        
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            
            // SQL Injection vulnerability - user input directly concatenated
            String query = "SELECT * FROM users WHERE username='" + username + 
                          "' AND password='" + password + "'";
            
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                // XSS vulnerability - reflecting user input without sanitization
                response.getWriter().write("<html><body>");
                response.getWriter().write("<h1>Welcome " + username + "!</h1>");
                response.getWriter().write("</body></html>");
            } else {
                response.getWriter().write("Login failed for user: " + username);
            }
            
            rs.close();
            stmt.close();
            conn.close();
            
        } catch (SQLException e) {
            // Information exposure through error messages
            response.getWriter().write("Database error: " + e.getMessage());
            e.printStackTrace(); // Logging sensitive information
        }
    }
    
    /**
     * Search users with SQL injection vulnerability
     */
    public String searchUsers(String searchTerm) {
        StringBuilder results = new StringBuilder();
        
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();
            
            // Another SQL injection point
            String query = "SELECT * FROM users WHERE name LIKE '%" + searchTerm + "%'";
            ResultSet rs = stmt.executeQuery(query);
            
            while (rs.next()) {
                results.append(rs.getString("name")).append("\n");
            }
            
            rs.close();
            stmt.close();
            conn.close();
            
        } catch (SQLException e) {
            return "Error: " + e.getMessage();
        }
        
        return results.toString();
    }
}
