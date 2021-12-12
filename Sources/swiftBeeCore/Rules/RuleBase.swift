//
//  RuleBase.swift
//  
//
//  Created by Benoit PASQUIER on 12/12/2021.
//

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
