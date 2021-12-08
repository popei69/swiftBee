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
    
    func analyze(_ file: File) {
        providers
            .map { $0.rules }
            .flatMap { $0 }
            .forEach { try? self.isFileMatch(file, rule: $0) }
    } 
    
    func isFileMatch(_ file: File, rule: Rule) throws -> Bool {
        
        let content = try file.readAsString()
        
        let regex = try? NSRegularExpression(pattern: rule.regex)
        
        let range = NSRange(location: 0, length: content.utf16.count)
        let result = regex?.matches(in: content, options: [], range: range)
        
        if result?.isEmpty == false {
            print("Found \(rule.cwe) in \(file.name)")
        }
        
        return result?.isEmpty ?? false
    }
}
