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
            Rule(regexExactMatch: "NSTemporaryDirectory\\(\\),",
                 cwe: "CWE-22",
                 averageCSVSS: 7.5,
                 description: "User use in \"NSTemporaryDirectory ()\" is unreliable, it can result in vulnerabilities in the directory.",
                 recommendation: ""),
            
            Rule(regexExactMatch: "\\w+.withUnsafeBytes\\s*{.*",
                 cwe: "CWE-789",
                 averageCSVSS: 4,
                 description: "Using this implementation of '.withUnsafeBytes' can lead to the compiler's decision to use unsafe APIs, such as _malloc and _strcpy, as the method calls closing with an UnsafeRawBufferPointer.",
                 recommendation: "Whenever possible, avoid using buffers or memory pointers that do not have a valid size."),
            
            Rule(regexExactMatch: "canAuthenticateAgainstProtectionSpace|continueWithoutCredentialForAuthenticationChallenge|kCFStreamSSLAllowsExpiredCertificates|kCFStreamSSLAllowsAnyRoot|kCFStreamSSLAllowsExpiredRoots|validatesSecureCertificate\\s*=\\s*(no|NO)|allowInvalidCertificates\\s*=\\s*(YES|yes)",
                 cwe: "CWE-295",
                 averageCSVSS: 7.4,
                 description: "The application allows self-signed or invalid SSL certificates. The application is vulnerable to MITM (Man-In-The-Middle) attacks.",
                 recommendation: "Certificates must be carefully managed and verified to ensure that data is encrypted with the intended owner's public key."),
            
            Rule(regexExactMatch: "setAllowsAnyHTTPSCertificate:\\s*YES|allowsAnyHTTPSCertificateForHost|loadingUnvalidatedHTTPSPage\\s*=\\s*(YES|yes)",
                 cwe: "CWE-295",
                 averageCSVSS: 7.4,
                 description: "The in-app UIWebView ignores SSL errors and accepts any SSL certificate. The application is vulnerable to attacks from MITM (Man-In-The-Middle).",
                 recommendation: "Certificates must be carefully managed and verified to ensure that data is encrypted with the intended owner's public key."),
            
            Rule(regexExactMatch: "kSecAttrAccessibleWhenUnlocked|kSecAttrAccessibleAfterFirstUnlock|SecItemAdd|SecItemUpdate|NSDataWritingFileProtectionComplete",
                 cwe: "CWE-695",
                 averageCSVSS: 5,
                 description: "Local File I/O Operations",
                 recommendation: ""),
            
            Rule(regexAnd: ["loadRequest", "WebView"],
                 regexNotAnd: ["WebView"],
                 cwe: "CWE-749",
                 averageCSVSS: 5,
                 description: "WebView Load Request.",
                 recommendation: ""),
            
            Rule(regexAnd: ["NSHTTPCookieStorage", "sharedHTTPCookieStorage"],
                 regexNotAnd: ["NSHTTPCookieStorage"],
                 cwe: "CWE-539",
                 averageCSVSS: 5.3,
                 description: "Cookie Storage.",
                 recommendation: ""),
            
            Rule(regexAnd: ["CommonDigest.h", "CC_MD5"],
                 regexNotAnd: ["CommonDigest.h"],
                 cwe: "CWE-327",
                 averageCSVSS: 7.4,
                 description: "MD5 is a weak hash, which can generate repeated hashes.",
                 recommendation: "When it is necessary to store or transmit sensitive data, give preference to modern encryption algorithms and check frequently that the algorithm used has not become obsolete."),
            
            Rule(regexExactMatch: "UIPasteboard",
                 cwe: "CWE-200",
                 averageCSVSS: 9.8,
                 description: "The application copies data to the UIPasteboard. Confidential data must not be copied to the UIPasteboard, as other applications can access it.",
                 recommendation: ""),
            
            Rule(regexAnd: ["loadHTMLString\\(", "WKWebView"],
                 regexNotAnd: ["WKWebView"],
                 cwe: "CWE-95",
                 averageCSVSS: 8.8,
                 description: "User input not sanitized in 'loadHTMLString' can result in an injection of JavaScript in the context of your application, allowing access to private data.",
                 recommendation: ""),
            
            Rule(regexOr: ["(?i)SHA1\\(", "CC_SHA1\\("],
                 cwe: "CWE-327",
                 averageCSVSS: 5.9,
                 description: "SHA1 is a weak hash, which can generate repeated hashes.",
                 recommendation: "When it is necessary to store or transmit sensitive data, give preference to modern encryption algorithms and check frequently that the algorithm used has not become obsolete."),
            
            Rule(regexOr: ["kCCOptionECBMode", "kCCAlgorithmAES"],
                 cwe: "CWE-327",
                 averageCSVSS: 5.9,
                 description: "The application uses ECB mode in the encryption algorithm. It is known that the ECB mode is weak, as it results in the same ciphertext for identical blocks of plain text.",
                 recommendation: "When it is necessary to store or transmit sensitive data, give preference to modern encryption algorithms and check frequently that the algorithm used has not become obsolete."),
            
            Rule(regexAnd: ["mach/mach_init.h", "MACH_PORT_VALID|mach_task_self\\(\\)"],
                 regexNotAnd: ["mach/mach_init.h"],
                 cwe: "CWE-215",
                 averageCSVSS: 5,
                 description: "The application has anti-debugger using Mach Exception Ports.",
                 recommendation: ""),
            
            
            Rule(regexOr: [
                    "CC_MD4_Init|CC_MD4_Update|CC_MD4_Final|CC_MD4|MD4_Ini",
                    "MD4_Update|MD4_Final|CC_MD5_Init|CC_MD5_Update|CC_MD5_Final|CC_MD5|MD5_Init",
                    "MD5_Update|MD5_Final|MD5Init|MD5Update|MD5Final"
                ],
                 cwe: "CWE-327",
                 averageCSVSS: 5.9,
                 description: "The app is using weak encryption APIs and / or that are known to have hash conflicts.",
                 recommendation: ""),
            
            
            Rule(regexOr: ["(?i)MD2\\(", "CC_MD2\\("],
                 cwe: "CWE-327",
                 averageCSVSS: 5.9,
                 description: "MD2 is a weak hash known to have hash collisions.",
                 recommendation: ""),
            
            
            Rule(regexOr: ["(?i)MD6\\(", "CC_MD6\\("],
                 cwe: "CWE-327",
                 averageCSVSS: 5.9,
                 description: "MD6 is a weak hash known to have hash collisions.",
                 recommendation: ""),
            
            Rule(regexOr: [
                    "/Applications/Cydia.app",
                    "/Library/MobileSubstrate/MobileSubstrate.dylib",
                    "/usr/sbin/sshd",
                    "etc/apt",
                    "cydia://",
                    "/var/lib/cydia",
                    "/Applications/FakeCarrier.app",
                    "/Applications/Icy.app",
                    "/Applications/IntelliScreen.app",
                    "/Applications/SBSettings.app",
                    "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
                    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
                    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
                    "/etc/ssh/sshd_config",
                    "/private/var/tmp/cydia.log",
                    "/usr/libexec/ssh-keysign",
                    "/Applications/MxTube.app",
                    "/Applications/RockApp.app",
                    "/Applications/WinterBoard.app",
                    "/Applications/blackra1n.app",
                    "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
                    "/private/var/lib/apt",
                    "/private/var/lib/cydia",
                    "/private/var/mobile/Library/SBSettings/Themes",
                    "/private/var/stash",
                    "/usr/bin/sshd",
                    "/usr/libexec/sftp-server",
                    "/var/cache/apt",
                    "/var/lib/apt",
                    "/usr/sbin/frida-server",
                    "/usr/bin/cycript",
                    "/usr/local/bin/cycript",
                    "/usr/lib/libcycript.dylib",
                    "frida-server"
                ],
                 cwe: "CWE-693",
                 averageCSVSS: 0,
                 description: "The application may contain Jailbreak detection mechanisms.",
                 recommendation: ""),
            
            Rule(regexAnd: ["UIPasteboard\\(", ".generalPasteboard"],
                 cwe: "CWE-200",
                 averageCSVSS: 5,
                 description: "Set or Read Clipboard",
                 recommendation: ""),
            
            Rule(regexExactMatch: "UIPasteboardChangedNotification|generalPasteboard\\]\\.string",
                 cwe: "CWE-200",
                 averageCSVSS: 5.0,
                 description: "The application allows you to list the changes on the Clipboard. Some malware also lists changes to the Clipboard.",
                 recommendation: ""),
            
            Rule(regexOr: ["sqlite3_exec", "sqlite3_finalize"],
                 cwe: "CWE-922",
                 averageCSVSS: 5.5,
                 description: "The application is using SQLite. Confidential information must be encrypted",
                 recommendation: ""),
            
            Rule(regexAnd: ["NSLog\\(|NSAssert\\(|fprintf\\(|fprintf\\(|Logging\\("],
                 regexNotAnd: ["\\*"],
                 cwe: "CWE-532",
                 averageCSVSS: 7.5,
                 description: "The binary can use the NSLog function for logging. Confidential information should never be recorded.",
                 recommendation: "Prevent sensitive data from being logged into production."),
            
            Rule(regexExactMatch: "(?i)\\.noFileProtection",
                 cwe: "CWE-311",
                 averageCSVSS: 4.3,
                 description: "The file has no special protections associated with it.",
                 recommendation: ""),
            
            Rule(regexAnd: ["\\.TLSMinimumSupportedProtocolVersion", "tls_protocol_version_t\\.TLSv10|tls_protocol_version_t\\.TLSv11"],
                 cwe: "",
                 averageCSVSS: 0,
                 description: "TLS 1.3 should be used. Detected old version.",
                 recommendation: ""),
            
            // TODO check
            Rule(regexAnd: ["\\.TLSMinimumSupportedProtocolVersion", "tls_protocol_version_t\\.TLSv12"],
                 cwe: "CWE-757",
                 averageCSVSS: 7.5,
                 description: "TLS 1.3 should be used. Detected old version - TLS 1.2.",
                 recommendation: ""),
            
            Rule(regexExactMatch: "strcpy\\(|memcpy\\(|strcat\\(|strncat\\(|strncpy\\(|sprintf\\(|vsprintf\\(|gets\\(",
                 cwe: "CWE-676",
                 averageCSVSS: 2.2,
                 description: "The application may contain prohibited APIs. These APIs are insecure and should not be used.",
                 recommendation: "Avoid using unsafe API (s) and never rely on data entered by the user, always sanitize the data entered."),
            
            Rule(regexExactMatch: "NSFileProtectionNone", 
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

