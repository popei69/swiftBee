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
                .map(analyseFiles)
            
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
    
    func analyseFiles(_ files: [File]) {
        let analyser = Analyzer()
        
        for file in files {
            do {
                try analyser.analyze(file)
            } catch {
                print(error)
            }
        }
    }

}

