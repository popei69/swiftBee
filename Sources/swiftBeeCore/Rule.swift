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

extension Rule: Codable { }
