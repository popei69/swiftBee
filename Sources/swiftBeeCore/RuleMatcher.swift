//
//  File.swift
//  
//
//  Created by Benoit PASQUIER on 08/12/2021.
//

import Foundation
import Files


final class RuleMatcher {
    
    let providers: [RuleProviderProtocol]
    
    init(providers: [RuleProviderProtocol] = [BasicRuleProvider()]) {
        self.providers = providers
    }
    
    func analyze(_ file: File) throws {
        
        let content = try file.readAsString()
        
        let issues = providers
            .map { $0.rules }
            .flatMap { $0 }
            .compactMap { rule in 
                return self.match(content, rule: rule)
            }
            .flatMap { $0 }
        
        for issue in issues {
            let log = """
            -------------------------------------
            Issue found
            ID: \(issue.vulnerabilityId)
            CSVV: \(issue.info.CSVSS)
            CWE: \(issue.info.cwe)
            Sample: \(issue.sample ?? "")
            Recommendation: \(issue.info.recommendation)
            -------------------------------------
            """
            print(log)
        }
    } 
    
    func match(_ content: String, rule: Rule) -> [Issue]? {
        let regex = try? NSRegularExpression(pattern: rule.regex)
        let range = NSRange(location: 0, length: content.utf16.count)
        
        guard let result = regex?.matches(in: content, options: [], range: range) else {
            return nil
        }
        
        let info = IssueInfo(rule: rule)
        
        let issues = result
            .compactMap { Range($0.range, in: content) }
            .compactMap { String(content[$0]) }
            .map { sample in 
                return Issue(vulnerabilityId: UUID(), info: info, line: nil, column: nil, sample: sample, content: nil)
            }
        
        return issues
    }
}

