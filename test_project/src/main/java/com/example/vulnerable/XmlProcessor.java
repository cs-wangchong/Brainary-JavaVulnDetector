package com.example.vulnerable;

import java.io.*;
import javax.xml.parsers.*;
import org.xml.sax.*;
import org.w3c.dom.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;

/**
 * XmlProcessor with XML External Entity (XXE) vulnerabilities
 * CWE-611: Improper Restriction of XML External Entity Reference
 */
public class XmlProcessor {
    
    /**
     * Parse XML with XXE vulnerability
     */
    public Document parseXml(String xmlContent) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            
            // XXE vulnerability - external entities not disabled
            // Should call: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            // Should call: factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            
            DocumentBuilder builder = factory.newDocumentBuilder();
            
            InputSource is = new InputSource(new StringReader(xmlContent));
            return builder.parse(is);
            
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    /**
     * Parse XML file with XXE vulnerability
     */
    public Document parseXmlFile(File xmlFile) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        
        // Missing security configuration
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(xmlFile);
    }
    
    /**
     * SAX parser with XXE vulnerability
     */
    public void parseSax(String xmlContent) {
        try {
            SAXParserFactory factory = SAXParserFactory.newInstance();
            
            // XXE vulnerability in SAX parser
            SAXParser saxParser = factory.newSAXParser();
            
            DefaultHandler handler = new DefaultHandler() {
                @Override
                public void startElement(String uri, String localName, 
                                       String qName, Attributes attributes) {
                    System.out.println("Start Element: " + qName);
                }
            };
            
            InputSource is = new InputSource(new StringReader(xmlContent));
            saxParser.parse(is, handler);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Transform XML with XXE vulnerability
     */
    public String transformXml(String xmlContent, String xsltContent) {
        try {
            TransformerFactory factory = TransformerFactory.newInstance();
            
            // XXE in XSLT transformation
            StreamSource xsltSource = new StreamSource(new StringReader(xsltContent));
            Transformer transformer = factory.newTransformer(xsltSource);
            
            StreamSource xmlSource = new StreamSource(new StringReader(xmlContent));
            StringWriter writer = new StringWriter();
            StreamResult result = new StreamResult(writer);
            
            transformer.transform(xmlSource, result);
            
            return writer.toString();
            
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
