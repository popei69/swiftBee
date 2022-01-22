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

    func generateReport(with issues: [Issue]) -> Report {

        var averageCSVSS: Float = 0

        var noneCount = 0
        var lowCount = 0
        var mediumCount = 0
        var highCount = 0
        var criticalCount = 0

        for issue in issues {
            let issueCSVSS = issue.info.CSVSS
            averageCSVSS = max(averageCSVSS, issueCSVSS)

            switch issueCSVSS {
            case 0:
                noneCount += 1
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
            lowCount: lowCount,
            mediumCount: mediumCount,
            highCount: highCount,
            criticalCount: criticalCount,
            totalCount: issues.count,
            issues: issues
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
