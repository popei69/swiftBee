//
//  File.swift
//  
//
//  Created by Benoit PASQUIER on 08/12/2021.
//

import Foundation

struct Rule {
    let regex: String

    /// Common Weakness Enumeration
    let cwe: String
    let averageCSVSS: Float
    let description: String
    let recommendation: String
}

extension Rule {
    init(regex: String, base: RuleBase, description: String) {
        self.regex = regex
        self.cwe = base.key
        self.averageCSVSS = base.CSVSS
        self.recommendation = base.recommendation
        self.description = description
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
