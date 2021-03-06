//
//  File.swift
//  
//
//  Created by Benoit PASQUIER on 08/12/2021.
//

import Foundation
import Files


final class Analyser {
    
    let providers: [RuleProviderProtocol]
    let targetFolder: Folder
    
    init(providers: [RuleProviderProtocol] = [BasicRuleProvider(), iOSRuleProvider()],
         targetFolder: Folder) {
        self.providers = providers
        self.targetFolder = targetFolder
    }
    
    func providerHandlers(for file: File) -> [RuleProviderProtocol] {
        guard let fileExtension = file.extension else {
            return []
        }
        
        return providers
            .filter { $0.supportedExtensions.isEmpty || $0.supportedExtensions.contains(fileExtension) }
    }
    
    func analyse(_ file: File) throws -> [Vulnerability] {
        let providerHandlers = providerHandlers(for: file)
        guard !providerHandlers.isEmpty else {
            return []
        }

        let relativePath = file.path(relativeTo: targetFolder)
        print("Analyzing : " + relativePath)
        let content = try file.readAsString()
        
        let vulnerabilities = providerHandlers
            .map { $0.rules }
            .flatMap { $0 }
            .compactMap { rule in
                self.evaluate(content, rule: rule)
            }
            .flatMap { $0 }
            .compactMap { Vulnerability(filePath: relativePath, issue: $0)
            }

        return vulnerabilities
        
//        for issue in issues {
//            let log = """
//            -------------------------------------
//            Issue found ⚠️
//            ID: \(issue.vulnerabilityId)
//            CSVV: \(issue.info.CSVSS)
//            CWE: \(issue.info.cwe)
//            Sample: \(issue.sample ?? "")
//            Recommendation: \(issue.info.recommendation)
//            File: \(file.path)
//            -------------------------------------
//            """
//            print(log)
//        }
    }
    
    func evaluate(_ content: String, rule: Rule) -> [Issue]? {
        if rule.hasAnd {
            return evaluateAndMatch(content, rule: rule)
        }
        
        if rule.hasOr {
            return evaluateOrMatch(content, rule: rule)
        }
            
        if rule.isMatch {
            return evaluateExactMatch(content, rule: rule)
        }
            
        return []
    }
    
    func evaluateExactMatch(_ content: String, rule: Rule) -> [Issue]? {
        guard let exactMatch = rule.regexExactMatch, !exactMatch.isEmpty else {
            return nil
        }
        
        var result: [Issue] = []
        let issues = evaluateRegex(exactMatch, into: content, from: rule) ?? []
        
        if rule.hasNotOr || rule.hasNotAnd {
            for issue in issues {
                guard let issueContent = issue.content else {
                    continue
                }
                
                if evaluateAllNot(issueContent, rule: rule) {
                    result.append(issue)
                }
            }
        } else {
            result.append(contentsOf: issues)
        }
        
        return result
    }
    
    /// Evaluate all the AND regex at once
    /// - Parameters:
    ///   - content: Content to evaluate
    ///   - rule: Rule
    /// - Returns: List of detected issues
    func evaluateAndMatch(_ content: String, rule: Rule) -> [Issue]? {
        guard let regexAnd = rule.regexAnd else {
            return nil
        }
        
        var result: [Issue] = []
        for regex in regexAnd {
            
            let issues = evaluateRegex(regex, into: content, from: rule) ?? []
            
            // if no match, we stop here for AND
            if issues.isEmpty {
                return nil
            }
            
            if rule.hasNotAnd || rule.hasNotOr {
                
                for issue in issues {
                    guard let issueContent = issue.content else {
                        continue
                    }
                    
                    if evaluateAllNot(issueContent, rule: rule) {
                        result.append(issue)
                    }
                }
            }
            
            result.append(contentsOf: issues)
        }
        
        return result
    }
    
    func evaluateOrMatch(_ content: String, rule: Rule) -> [Issue]? {
        guard let regexOr = rule.regexOr else {
            return nil
        }
        
        var result: [Issue] = []
        for regex in regexOr {
            let issues = evaluateRegex(regex, into: content, from: rule) ?? []
            // TODO handle NOT OR / NOT AND
            
            result.append(contentsOf: issues)
        }
        
        return result
    }
    
    func evaluateAllNot(_ content: String, rule: Rule) -> Bool {
        if rule.hasNotAnd {
            return evaluateNotAndMatch(content, rule: rule)
        }
        
        if rule.hasNotOr {
            return evaluateNotOrMatch(content, rule: rule)
        }
        
        return true
    }
    
    func evaluateNotAndMatch(_ content: String, rule: Rule) -> Bool {
        guard let regexNotAnd = rule.regexNotAnd else {
            return true
        }
        
        var found = 0
        for regex in regexNotAnd {
            let matches = findAll(regex, into: content) ?? []
            
            if !matches.isEmpty {
                found += 1
            }
        }
        
        return regexNotAnd.count == found
    }
    
    func evaluateNotOrMatch(_ content: String, rule: Rule) -> Bool {
        guard let regexNotOr = rule.regexNotOr else {
            return true
        }
        
        for regex in regexNotOr {
            if containsOne(regex, into: content) {
                return false
            }
        }
        
        return true
    }
}

extension Analyser {
    
    private func evaluateRegex(_ regexExp: String, into content: String, from rule: Rule) -> [Issue]? {
        guard let result = findAll(regexExp, into: content),
                !result.isEmpty else {
            return nil
        }
        
        let info = IssueInfo(rule: rule)
        
        let issues = result
            .map { sample in
                return Issue(vulnerabilityId: UUID(), info: info, line: nil, column: nil, sample: sample, content: sample)
            }
        
        return issues
    }
    
    private func findAll(_ regexExp: String, into content: String) -> [String]? {
        let regex = try? NSRegularExpression(pattern: regexExp)
        let range = NSRange(location: 0, length: content.utf16.count)
        return regex?.matches(in: content, options: [], range: range)
            .compactMap { Range($0.range, in: content) }
            .compactMap { String(content[$0]) }
    }
    
    private func containsOne(_ regexExp: String, into content: String) -> Bool {
        let regex = try? NSRegularExpression(pattern: regexExp)
        let range = NSRange(location: 0, length: content.utf16.count)
        return regex?.matches(in: content, options: [], range: range).isEmpty ?? true
    }
}
