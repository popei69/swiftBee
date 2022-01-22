//
//  Core.swift
//  
//
//  Created by Benoit PASQUIER on 08/12/2021.
//

import Foundation
import Files

enum Error: Swift.Error {
    case missingFolderPath
    case unknownFolderPath
    case failedToCreateFile
}

public final class CommandLineTool {
    private let arguments: [String]

    public init(arguments: [String] = CommandLine.arguments) { 
        self.arguments = arguments
    }

    public func run() throws {
        let start = Date()
        guard arguments.count > 1 else {
            throw Error.missingFolderPath
        }
        
        let path = arguments[1]
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
        let scanner = Scanner()
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

