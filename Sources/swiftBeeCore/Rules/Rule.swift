//
//  File.swift
//  
//
//  Created by Benoit PASQUIER on 08/12/2021.
//

import Foundation

struct Rule {
    /// Common Weakness Enumeration
    let cwe: String
    let averageCSVSS: Float
    let description: String
    let recommendation: String
    
    // one regex only
    let regexExactMatch: String?
    
    // "AND" operator on multiple expressions
    let regexAnd: [String]?
    
    // "OR" operator on multiple expressions
    let regexOr: [String]?
    
    // "NOT AND" operator on multiple expressions
    let regexNotAnd: [String]?
    
    // "NOT OR" operator on multiple expressions
    let regexNotOr: [String]?
    
    init(
        regexExactMatch: String? = nil,
        regexAnd: [String]? = nil,
        regexOr: [String]? = nil,
        regexNotAnd: [String]? = nil,
        regexNotOr: [String]? = nil,
        cwe: String,
        averageCSVSS: Float,
        description: String,
        recommendation: String) {
        self.cwe = cwe
        self.averageCSVSS = averageCSVSS
        self.description = description
        self.recommendation = recommendation
        self.regexExactMatch = regexExactMatch
        self.regexAnd = regexAnd
        self.regexOr = regexOr
        self.regexNotAnd = regexNotAnd
        self.regexNotOr = regexNotOr
    }

}

extension Rule {
    
    init(regexExactMatch: String, base: RuleBase, description: String) {
        self.init(regexExactMatch: regexExactMatch,
                  regexAnd: nil,
                  regexOr: nil,
                  regexNotAnd: nil,
                  regexNotOr: nil,
                  cwe: base.key,
                  averageCSVSS: base.CSVSS,
                  description: description,
                  recommendation: base.recommendation)
        
    }
}
