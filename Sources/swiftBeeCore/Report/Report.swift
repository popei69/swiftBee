//
//  File.swift
//  
//
//  Created by Benoit Pasquier on 22/1/22.
//

import Foundation

struct Report {
    let averageCSVSS: Float
    let securityScore: Float

    // vulnerability counts
    let lowCount: Int
    let mediumCount: Int
    let highCount: Int
    let criticalCount: Int
    let totalCount: Int
}
