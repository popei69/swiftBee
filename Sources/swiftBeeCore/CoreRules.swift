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
            Rule(regex: "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", 
                 cwe: "CWE-312", 
                 averageCSVSS: 7, 
                 description: "File contains sensitive information written directly, such as usernames, passwords, keys, etc.", 
                 recommendation: "Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.")
        ]
    }
}
