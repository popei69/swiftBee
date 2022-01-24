//
//  Core.swift
//  
//
//  Created by Benoit PASQUIER on 08/12/2021.
//

import Foundation
import ArgumentParser
import Files

enum Error: Swift.Error {
    case missingFolderPath
    case unknownFolderPath
    case failedToCreateFile
}

@main
struct SwiftBee: ParsableCommand {

    @Flag(help: "Ignore CocoaPods dependencies")
    var ignorePods = false

    @Argument(help: "Folder path to scan")
    var path: String

    mutating func run() throws {
        let start = Date()
        guard !path.isEmpty else {
            throw Error.missingFolderPath
        }

        do {
            let folder = try Folder(path: path) 
            scanFolder(folder)
                .map({ self.analyseFiles($0, from: folder) })
                .map({ self.publishReport($0, destination: folder) })
            
        } catch {
            throw Error.unknownFolderPath
        }
        
        let interval = Date().timeIntervalSince(start)
        print("⏲ - \(interval)")
    }
    
    func scanFolder(_ folder: Folder) -> [File]? {
        let scanner = Scanner(ignorePods: ignorePods)
        return scanner.scan(folder)
    }
    
    func analyseFiles(_ files: [File], from targetFolder: Folder) -> [Vulnerability] {
        let analyser = Analyser(targetFolder: targetFolder)

        var result: [Vulnerability] = []
        
        for file in files {
            do {
                let tmp = try analyser.analyse(file)
                result.append(contentsOf: tmp)
            } catch {
                print(error)
            }
        }

        return result
    }

    func publishReport(_ vulnerabilities: [Vulnerability], destination: Folder) {
        let reporter = Reporter(folderDestination: destination, fileName: "report.json")
        let report = reporter.generateReport(with: vulnerabilities)
        do {
            try reporter.publishReport(report)
        } catch {
            print(error)
        }
    }

}

