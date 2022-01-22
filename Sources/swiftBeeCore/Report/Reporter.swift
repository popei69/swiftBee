//
//  File.swift
//  
//
//  Created by Benoit Pasquier on 22/1/22.
//

import Foundation
import Files

final class Reporter {

    let folderDestination: Folder
    let fileName: String

    init(folderDestination: Folder, fileName: String) {
        self.folderDestination = folderDestination
        self.fileName = fileName
    }

    func generateReport(with vulnerabilities: [Vulnerability]) -> Report {

        var averageCSVSS: Float = 0

        var unknownCount = 0
        var lowCount = 0
        var mediumCount = 0
        var highCount = 0
        var criticalCount = 0

        for vulnerability in vulnerabilities {
            let issueCSVSS = vulnerability.issue.info.CSVSS
            averageCSVSS = max(averageCSVSS, issueCSVSS)

            switch issueCSVSS {
            case 0:
                unknownCount += 1
            case 0..<4:
                lowCount += 1
            case 4..<7:
                mediumCount += 1
            case 7..<9:
                highCount += 1
            case 9...10:
                criticalCount += 1
            default:
                debugPrint("Unexpected issue score")
            }
        }

        let securityScore = calculateSecurityScore(averageCSVSS)
        let report = Report(
            averageCSVSS: averageCSVSS,
            securityScore: securityScore,
            unknownCount: unknownCount,
            lowCount: lowCount,
            mediumCount: mediumCount,
            highCount: highCount,
            criticalCount: criticalCount,
            totalCount: vulnerabilities.count,
            vulnerabilities: vulnerabilities
        )

        return report
    }

    func publishReport(_ report: Report) throws {
        let data = try JSONEncoder().encode(report)
        _ = try folderDestination.createFileIfNeeded(withName: fileName, contents: data)
    }
}

extension Reporter {
    private func calculateSecurityScore(_ averageCSVSS: Float) -> Float {
        return 100.0 - (10 * averageCSVSS)
    }
}
