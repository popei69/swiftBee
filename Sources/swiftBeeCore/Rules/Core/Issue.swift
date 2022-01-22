//
//  File.swift
//  
//
//  Created by Benoit Pasquier on 23/12/21.
//

import Foundation

struct Issue {
    let vulnerabilityId: UUID
    let info: IssueInfo
    let line: Int?
    let column: Int?
    let sample: String?
    let content: String?
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
