package com.example.vulnerable;

import java.io.*;
import java.util.*;
import org.apache.logging.log4j.*;

/**
 * DataProcessor with insecure deserialization and command injection vulnerabilities
 * CWE-502: Deserialization of Untrusted Data
 * CWE-78: OS Command Injection
 */
public class DataProcessor {
    
    private static final Logger logger = LogManager.getLogger(DataProcessor.class);
    
    /**
     * Deserialize untrusted data - major security vulnerability
     */
    public Object loadObject(InputStream inputStream) {
        try {
            ObjectInputStream ois = new ObjectInputStream(inputStream);
            // Insecure deserialization - can lead to remote code execution
            Object obj = ois.readObject();
            ois.close();
            return obj;
        } catch (Exception e) {
            logger.error("Deserialization failed", e);
            return null;
        }
    }
    
    /**
     * Load serialized object from file
     */
    public Object loadFromFile(String filename) throws Exception {
        FileInputStream fis = new FileInputStream(filename);
        ObjectInputStream ois = new ObjectInputStream(fis);
        
        // Another insecure deserialization point
        Object data = ois.readObject();
        
        ois.close();
        fis.close();
        
        return data;
    }
    
    /**
     * Execute system command with user input - command injection
     */
    public String executeCommand(String userInput) {
        try {
            // Command injection vulnerability
            String command = "ls -la " + userInput;
            Process process = Runtime.getRuntime().exec(command);
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            return output.toString();
            
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }
    
    /**
     * Process user files with command injection
     */
    public void convertFile(String inputFile, String outputFile) throws IOException {
        // Command injection through file paths
        String[] cmd = {
            "/bin/sh",
            "-c",
            "convert " + inputFile + " " + outputFile
        };
        
        Runtime.getRuntime().exec(cmd);
    }
    
    /**
     * Log user input with Log4j (vulnerable version)
     */
    public void logUserActivity(String username, String action) {
        // Log4Shell vulnerability (CVE-2021-44228) in Log4j 2.14.1
        // JNDI lookup in log messages can lead to RCE
        logger.info("User {} performed action: {}", username, action);
    }
    
    /**
     * Execute script with user input
     */
    public void runScript(String scriptName, String parameter) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(
            "python",
            scriptName,
            parameter  // User input passed directly to command
        );
        
        pb.start();
    }
}
