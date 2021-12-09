//
//  File.swift
//  
//
//  Created by Benoit PASQUIER on 08/12/2021.
//

import Foundation

protocol RuleProviderProtocol { 
    var rules: [Rule] { get }
}

final class iOSRuleProvider {
    
}

final class BasicRuleProvider: RuleProviderProtocol { 
    lazy var rules: [Rule] = BasicRuleProvider.makeBasicRules()
    
    static func makeBasicRules() -> [Rule] {
        return [
            Rule(regex: "\\d{2,3}\\.\\d{2,3}\\.\\d{2,3}\\.\\d{2,3}", 
                 base: .cwe312,  
                 description: RuleBase.cwe312.description),
            
            Rule(regex: "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", 
                 base: .cwe312, 
                 description: RuleBase.cwe312.description),
            
            Rule(regex: "(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z/+]{40}['\"]", 
                 base: .cwe312, 
                 description: RuleBase.cwe312.description),
            
            Rule(regex: "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", 
                 base: .cwe312, 
                 description: RuleBase.cwe312.description),
            
            Rule(regex: "(chave\\s*=\\s*['|\"]\\w+['|\"])|(\\w*[tT]oken\\s*=\\s*['|\"]\\w+['|\"])|(\\w*[aA][uU][tT][hH]\\w*\\s*=\\s*['|\"]\\w+['|\"])|(username\\s*=\\s*['|\"]\\w+['|\"])|(secret\\s*=\\s*['|\"]\\w+['|\"])|(chave\\s*=\\s*['|\"]\\w+['|\"])", 
                 // NotOr:         []*regexp.Regexp{regexp.MustCompile(`(?mi)public.*[tT]oken`),
                 base: .cwe312, 
                 description: RuleBase.cwe312.description),
            
            Rule(regex: "-----BEGIN PRIVATE KEY-----", 
                 base: .cwe312, 
                 description: RuleBase.cwe312.description),
            
            Rule(regex: "AAAA(?:[0-9A-Za-z+/])+={0,3}(?:.+@.+)", 
                 base: .cwe312, 
                 description: RuleBase.cwe312.description),
            
            Rule(regex: "-----BEGIN OPENSSH PRIVATE KEY-----", 
                 base: .cwe312, 
                 description: RuleBase.cwe312.description),
            
            Rule(regex: "-----BEGIN PGP PRIVATE KEY BLOCK-----", 
                 base: .cwe312, 
                 description: RuleBase.cwe312.description),
            
            Rule(regex: "(?i)(facebook|fb)(.{0,20})?(?-i)['\"][0-9a-f]{32}['\"]", 
                 base: .cwe312, 
                 description: "Facebook Secret Key. " + RuleBase.cwe312.description),
            
            Rule(regex: "(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}['\"]", 
                 base: .cwe312, 
                 description: "Facebook Secret Key. " + RuleBase.cwe312.description),
            
            Rule(regex: "EAACEdEose0cBA[0-9A-Za-z]+", 
                 base: .cwe312, 
                 description: "Facebook Secret Key. " + RuleBase.cwe312.description),
            
            Rule(regex: "(?i)twitter(.{0,20})?['\"][0-9a-z]{35,44}['\"]", 
                 base: .cwe312, 
                 description: "Twitter Secret Key. " + RuleBase.cwe312.description),
            
            Rule(regex: "(?i)twitter(.{0,20})?['\"][0-9a-z]{18,25}['\"]", 
                 base: .cwe312, 
                 description: "Twitter Secret Key. " + RuleBase.cwe312.description),
            
            Rule(regex: "(?i)github(.{0,20})?(?-i)['\"][0-9a-zA-Z]{35,40}['\"]", 
                 base: .cwe312, 
                 description: "GitHub URL. " + RuleBase.cwe312.description),
            
            Rule(regex: "(?i)linkedin(.{0,20})?(?-i)['\"][0-9a-z]{12}['\"]", 
                 base: .cwe312, 
                 description: "LinkedIn Client ID. " + RuleBase.cwe312.description),
            
            Rule(regex: "(?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]", 
                 base: .cwe312, 
                 description: "LinkedIn Client ID. " + RuleBase.cwe312.description),
            
            Rule(regex: "xox[baprs]-([0-9a-zA-Z]{10,48})?", 
                 base: .cwe312, 
                 description: "Slack API key. " + RuleBase.cwe312.description),
            
            Rule(regex: "-----BEGIN EC PRIVATE KEY-----", 
                 base: .cwe312, 
                 description: "EC key. " + RuleBase.cwe312.description),
            
            // TODO check ApiKey?
            Rule(regex: "(?i)api_key(.{0,20})?['\"][0-9a-zA-Z]{32,45}['\"]", 
                 base: .cwe312, 
                 description: "Generic API key. " + RuleBase.cwe312.description),
            
            Rule(regex: "AIza[0-9A-Za-z\\-_]{35}", 
                 base: .cwe312, 
                 description: "Google API key. " + RuleBase.cwe312.description),
            
            Rule(regex: "(?i)(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z\\-_]{35}]['\"]", 
                 base: .cwe312, 
                 description: "Google Cloud Platform API key. " + RuleBase.cwe312.description),
            
            Rule(regex: "(?i)(google|gcp|auth)(.{0,20})?['\"][0-9]+-[0-9a-z_]{32}\\.apps\\.googleusercontent\\.com['\"]", 
                 base: .cwe312, 
                 description: "Google OAuth. " + RuleBase.cwe312.description),
            
            Rule(regex: "ya29\\.[0-9A-Za-z\\-_]+", 
                 base: .cwe312, 
                 description: "Google OAuth Access Token. " + RuleBase.cwe312.description),
            
            Rule(regex: "(?i)heroku(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", 
                 base: .cwe312, 
                 description: "Heroku API key. " + RuleBase.cwe312.description),
            
            Rule(regex: "(?i)(mailchimp|mc)(.{0,20})?['\"][0-9a-f]{32}-us[0-9]{1,2}['\"]", 
                 base: .cwe312, 
                 description: "MailChimp API key. " + RuleBase.cwe312.description),
            
            Rule(regex: "(?i)(mailgun|mg)(.{0,20})?['\"][0-9a-z]{32}['\"]", 
                 base: .cwe312, 
                 description: "Mailgun API key. " + RuleBase.cwe312.description),
            
            Rule(regex: "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}/?.?", 
                 base: .cwe312, 
                 description: "Password in URL. " + RuleBase.cwe312.description),
            
            Rule(regex: "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}", 
                 base: .cwe312, 
                 description: "PayPal Braintree Access Token. " + RuleBase.cwe312.description),
            
            Rule(regex: "sk_live_[0-9a-z]{32}", 
                 base: .cwe312, 
                 description: "Picatic API key. " + RuleBase.cwe312.description),
            
            Rule(regex: "(?i)stripe(.{0,20})?['\"][sk|rk]_live_[0-9a-zA-Z]{24}", 
                 base: .cwe312, 
                 description: "Stripe API key. " + RuleBase.cwe312.description),
            
            Rule(regex: "sq0atp-[0-9A-Za-z\\-_]{22}", 
                 base: .cwe312, 
                 description: "Square access token. " + RuleBase.cwe312.description),
            
            Rule(regex: "sq0csp-[0-9A-Za-z\\-_]{43}", 
                 base: .cwe312, 
                 description: "Square OAuth secret. " + RuleBase.cwe312.description),
            
            Rule(regex: "(?i)twilio(.{0,20})?['\"][0-9a-f]{32}['\"]", 
                 base: .cwe312, 
                 description: "Twilio API key. " + RuleBase.cwe312.description),
            
            Rule(regex: "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}", 
                 base: .cwe312, 
                 description: "Incoming Webhooks from Slack application."),
            
            Rule(regex: "(password\\s*=\\s*['|\"](.*)+['|\"])|(pass\\s*=\\s*['|\"](.*)+['|\"]\\s)|(pwd\\s*=\\s*['|\"](.*)+['|\"]\\s)|(passwd\\s*=\\s*['|\"](.*)+['|\"]\\s)|(senha\\s*=\\s*['|\"](.*)+['|\"])", 
                 base: .cwe312, 
                 description: RuleBase.cwe312.description),
            
            Rule(regex: "-----BEGIN CERTIFICATE-----", 
                 base: .cwe312, 
                 description: RuleBase.cwe312.description),
        ]
    }
}

enum RuleBase: String {
    case cwe312 = "CWE-312"
    
    var key: String {
        return rawValue
    }
    
    var CSVSS: Float {
        switch self {
        case .cwe312:
            return 7.4
        
        }
    }
    
    var description: String {
        switch self {
        case .cwe312:
            return "File contains sensitive information written directly, such as usernames, passwords, keys, etc."
        }
    }
    
    var recommendation: String {
        switch self {
        case .cwe312:
            return "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources."
        }
    }
}
