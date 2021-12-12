//
//  File.swift
//  
//
//  Created by Benoit PASQUIER on 12/12/2021.
//

import Foundation

final class iOSRuleProvider: RuleProviderProtocol { 
    lazy var rules: [Rule] = BasicRuleProvider.makeBasicRules()
    var supportedExtensions: [String] = ["swift", "obj", "h", "m"]
    
    static func makeBasicRules() -> [Rule] {
        return [
            Rule(regex: "NSTemporaryDirectory\\(\\),", 
                 cwe: "CWE-22",
                 averageCSVSS: 7.5,
                 description: "User use in \"NSTemporaryDirectory ()\" is unreliable, it can result in vulnerabilities in the directory.",
                 recommendation: ""),
            
            Rule(regex: "\\w+.withUnsafeBytes\\s*{.*", 
                 cwe: "CWE-789",
                 averageCSVSS: 4,
                 description: "Using this implementation of '.withUnsafeBytes' can lead to the compiler's decision to use unsafe APIs, such as _malloc and _strcpy, as the method calls closing with an UnsafeRawBufferPointer.",
                 recommendation: "Whenever possible, avoid using buffers or memory pointers that do not have a valid size."),
            
            Rule(regex: "canAuthenticateAgainstProtectionSpace|continueWithoutCredentialForAuthenticationChallenge|kCFStreamSSLAllowsExpiredCertificates|kCFStreamSSLAllowsAnyRoot|kCFStreamSSLAllowsExpiredRoots|validatesSecureCertificate\\s*=\\s*(no|NO)|allowInvalidCertificates\\s*=\\s*(YES|yes)", 
                 cwe: "CWE-295",
                 averageCSVSS: 7.4,
                 description: "The application allows self-signed or invalid SSL certificates. The application is vulnerable to MITM (Man-In-The-Middle) attacks.",
                 recommendation: "Certificates must be carefully managed and verified to ensure that data is encrypted with the intended owner's public key."),
            
            Rule(regex: "setAllowsAnyHTTPSCertificate:\\s*YES|allowsAnyHTTPSCertificateForHost|loadingUnvalidatedHTTPSPage\\s*=\\s*(YES|yes)", 
                 cwe: "CWE-295",
                 averageCSVSS: 7.4,
                 description: "The in-app UIWebView ignores SSL errors and accepts any SSL certificate. The application is vulnerable to attacks from MITM (Man-In-The-Middle).",
                 recommendation: "Certificates must be carefully managed and verified to ensure that data is encrypted with the intended owner's public key."),
            
            Rule(regex: "kSecAttrAccessibleWhenUnlocked|kSecAttrAccessibleAfterFirstUnlock|SecItemAdd|SecItemUpdate|NSDataWritingFileProtectionComplete", 
                 cwe: "CWE-695",
                 averageCSVSS: 5,
                 description: "Local File I/O Operations",
                 recommendation: ""),
            
            Rule(regex: "UIPasteboard", 
                 cwe: "CWE-200",
                 averageCSVSS: 9.8,
                 description: "The application copies data to the UIPasteboard. Confidential data must not be copied to the UIPasteboard, as other applications can access it.",
                 recommendation: ""),
            
            Rule(regex: "UIPasteboardChangedNotification|generalPasteboard\\]\\.string", 
                 cwe: "CWE-200",
                 averageCSVSS: 5.0,
                 description: "The application allows you to list the changes on the Clipboard. Some malware also lists changes to the Clipboard.",
                 recommendation: ""),
            
            Rule(regex: "(?i)\\.noFileProtection", 
                 cwe: "CWE-311",
                 averageCSVSS: 4.3,
                 description: "The file has no special protections associated with it.",
                 recommendation: ""),
            
            Rule(regex: "strcpy\\(|memcpy\\(|strcat\\(|strncat\\(|strncpy\\(|sprintf\\(|vsprintf\\(|gets\\(", 
                 cwe: "CWE-676",
                 averageCSVSS: 2.2,
                 description: "The application may contain prohibited APIs. These APIs are insecure and should not be used.",
                 recommendation: "Avoid using unsafe API (s) and never rely on data entered by the user, always sanitize the data entered."),
            
            Rule(regex: "NSFileProtectionNone", 
                 cwe: "CWE-311",
                 averageCSVSS: 4.3,
                 description: "The file has no special protections associated with it.",
                 recommendation: ""),
            
            // TODO  "CWE-749", CWE-539 "CWE-327", "CWE-95", "CWE-327", "CWE-327",
            // "CWE-215", "CWE-327", "CWE-693",
            // "CWE-200",  "CWE-922", "CWE-532", "CWE-757", ""
            
            
            
        ]
    }
}

