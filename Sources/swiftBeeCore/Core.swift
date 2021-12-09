//
//  File.swift
//  
//
//  Created by Benoit PASQUIER on 08/12/2021.
//

import Foundation
import Files

enum Error: Swift.Error {
    case missingfileName
    case failedToCreateFile
}

public final class CommandLineTool {
    private let arguments: [String]

    public init(arguments: [String] = CommandLine.arguments) { 
        self.arguments = arguments
    }

    public func run() throws {
        guard arguments.count > 1 else {
            throw Error.missingfileName
        }
        
        let fileName = arguments[1]
        
        do {
            let file = try Folder.current.file(named: fileName)
            
            let matcher = RuleMatcher()
            try matcher.analyze(file)
        } catch { 
            print(error)
            throw Error.failedToCreateFile
        }
    }
}

