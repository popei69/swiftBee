//
//  File.swift
//  
//
//  Created by Benoit PASQUIER on 08/12/2021.
//

import Foundation

final class BasicRuleProvider: RuleProviderProtocol { 
    lazy var rules: [Rule] = BasicRuleProvider.makeBasicRules()
    let supportedExtensions: [String] = []
    
    static func makeBasicRules() -> [Rule] {
        return [
            Rule(regexExactMatch: "\\d{2,3}\\.\\d{2,3}\\.\\d{2,3}\\.\\d{2,3}",
                 base: .cwe312,  
                 description: RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
                 base: .cwe312, 
                 description: RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z/+]{40}['\"]",
                 base: .cwe312, 
                 description: RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                 base: .cwe312, 
                 description: RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "(chave\\s*=\\s*['|\"]\\w+['|\"])|(\\w*[tT]oken\\s*=\\s*['|\"]\\w+['|\"])|(\\w*[aA][uU][tT][hH]\\w*\\s*=\\s*['|\"]\\w+['|\"])|(username\\s*=\\s*['|\"]\\w+['|\"])|(secret\\s*=\\s*['|\"]\\w+['|\"])|(chave\\s*=\\s*['|\"]\\w+['|\"])",
                 // NotOr:         []*regexp.Regexp{regexp.MustCompile(`(?mi)public.*[tT]oken`),
                 base: .cwe312, 
                 description: RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "-----BEGIN PRIVATE KEY-----",
                 base: .cwe312, 
                 description: RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "AAAA(?:[0-9A-Za-z+/])+={0,3}(?:.+@.+)",
                 base: .cwe312, 
                 description: RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "-----BEGIN OPENSSH PRIVATE KEY-----",
                 base: .cwe312, 
                 description: RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "-----BEGIN PGP PRIVATE KEY BLOCK-----",
                 base: .cwe312, 
                 description: RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "(?i)(facebook|fb)(.{0,20})?(?-i)['\"][0-9a-f]{32}['\"]",
                 base: .cwe312, 
                 description: "Facebook Secret Key. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}['\"]",
                 base: .cwe312, 
                 description: "Facebook Secret Key. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "EAACEdEose0cBA[0-9A-Za-z]+",
                 base: .cwe312, 
                 description: "Facebook Secret Key. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "(?i)twitter(.{0,20})?['\"][0-9a-z]{35,44}['\"]",
                 base: .cwe312, 
                 description: "Twitter Secret Key. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "(?i)twitter(.{0,20})?['\"][0-9a-z]{18,25}['\"]",
                 base: .cwe312, 
                 description: "Twitter Secret Key. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "(?i)github(.{0,20})?(?-i)['\"][0-9a-zA-Z]{35,40}['\"]",
                 base: .cwe312, 
                 description: "GitHub URL. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "(?i)linkedin(.{0,20})?(?-i)['\"][0-9a-z]{12}['\"]",
                 base: .cwe312, 
                 description: "LinkedIn Client ID. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "(?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]",
                 base: .cwe312, 
                 description: "LinkedIn Client ID. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "xox[baprs]-([0-9a-zA-Z]{10,48})?",
                 base: .cwe312, 
                 description: "Slack API key. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "-----BEGIN EC PRIVATE KEY-----",
                 base: .cwe312, 
                 description: "EC key. " + RuleBase.cwe312.description),
            
            // TODO check ApiKey?
            Rule(regexExactMatch: "(?i)api_key(.{0,20})?['\"][0-9a-zA-Z]{32,45}['\"]",
                 base: .cwe312, 
                 description: "Generic API key. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "AIza[0-9A-Za-z\\-_]{35}",
                 base: .cwe312, 
                 description: "Google API key. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "(?i)(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z\\-_]{35}]['\"]",
                 base: .cwe312, 
                 description: "Google Cloud Platform API key. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "(?i)(google|gcp|auth)(.{0,20})?['\"][0-9]+-[0-9a-z_]{32}\\.apps\\.googleusercontent\\.com['\"]",
                 base: .cwe312, 
                 description: "Google OAuth. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "ya29\\.[0-9A-Za-z\\-_]+",
                 base: .cwe312, 
                 description: "Google OAuth Access Token. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "(?i)heroku(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]",
                 base: .cwe312, 
                 description: "Heroku API key. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "(?i)(mailchimp|mc)(.{0,20})?['\"][0-9a-f]{32}-us[0-9]{1,2}['\"]",
                 base: .cwe312, 
                 description: "MailChimp API key. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "(?i)(mailgun|mg)(.{0,20})?['\"][0-9a-z]{32}['\"]",
                 base: .cwe312, 
                 description: "Mailgun API key. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}/?.?",
                 base: .cwe312, 
                 description: "Password in URL. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
                 base: .cwe312, 
                 description: "PayPal Braintree Access Token. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "sk_live_[0-9a-z]{32}",
                 base: .cwe312, 
                 description: "Picatic API key. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "(?i)stripe(.{0,20})?['\"][sk|rk]_live_[0-9a-zA-Z]{24}",
                 base: .cwe312, 
                 description: "Stripe API key. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "sq0atp-[0-9A-Za-z\\-_]{22}",
                 base: .cwe312, 
                 description: "Square access token. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "sq0csp-[0-9A-Za-z\\-_]{43}",
                 base: .cwe312, 
                 description: "Square OAuth secret. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "(?i)twilio(.{0,20})?['\"][0-9a-f]{32}['\"]",
                 base: .cwe312, 
                 description: "Twilio API key. " + RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
                 base: .cwe312, 
                 description: "Incoming Webhooks from Slack application."),
            
            Rule(regexExactMatch: "(password\\s*=\\s*['|\"](.*)+['|\"])|(pass\\s*=\\s*['|\"](.*)+['|\"]\\s)|(pwd\\s*=\\s*['|\"](.*)+['|\"]\\s)|(passwd\\s*=\\s*['|\"](.*)+['|\"]\\s)|(senha\\s*=\\s*['|\"](.*)+['|\"])",
                 base: .cwe312, 
                 description: RuleBase.cwe312.description),
            
            Rule(regexExactMatch: "-----BEGIN CERTIFICATE-----", 
                 base: .cwe312, 
                 description: RuleBase.cwe312.description),
        ]
    }
}
