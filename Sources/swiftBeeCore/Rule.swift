//
//  File.swift
//  
//
//  Created by Benoit PASQUIER on 08/12/2021.
//

import Foundation

struct Rule {
    let regex: String
    
    let base: RuleBase
    let description: String

    /// Common Weakness Enumeration
    var cwe: String {
        return base.key
    }
    
    var averageCSVSS: Float {
        return base.CSVSS
    }
    
    var recommendation: String {
        return base.recommendation
    } 
}

struct IssueInfo {
    let description: String
    let cwe: String
    let CSVSS: Float
    let recommendation: String
}

extension IssueInfo {
    init(rule: Rule) {
        self.description = rule.description
        self.cwe = rule.cwe
        self.CSVSS = rule.averageCSVSS
        self.recommendation = rule.recommendation
    }
}

struct Issue {
    let vulnerabilityId: UUID
    let info: IssueInfo
    let line: Int?
    let column: Int?
    let sample: String?
    let content: String?
}
