//
//  File.swift
//  
//
//  Created by Benoit Pasquier on 22/1/22.
//

import Foundation

struct Report: Codable {
    let averageCSVSS: Float
    let securityScore: Float

    // vulnerability counts
    var unknownCount: Int
    var lowCount: Int
    var mediumCount: Int
    var highCount: Int
    var criticalCount: Int
    var totalCount: Int

    var vulnerabilities: [Vulnerability]
}

extension Report {

    init(averageCSVSS: Float, securityScore: Float) {
        self.init(averageCSVSS: averageCSVSS,
                  securityScore: securityScore,
                  unknownCount: 0,
                  lowCount: 0,
                  mediumCount: 0,
                  highCount: 0,
                  criticalCount: 0,
                  totalCount: 0,
                  vulnerabilities: [])
    }
}
