//
//  Scanner.swift
//  
//
//  Created by Benoit PASQUIER on 12/12/2021.
//

import Files

struct Scanner {

    let ignorePods: Bool
    var exclusionFiles = [".gitignore"] 
    
    func scan(_ folder: Folder) -> [File] {
        guard canScan(folder) else {
            return []
        }
        
        var files = folder.files
            .filter { !exclusionFiles.contains($0.name) }
        
        for subfolder in folder.subfolders {
            files.append(contentsOf: scan(subfolder))
        }
        
        return files
    }
}

extension Scanner {
    private func canScan(_ folder: Folder) -> Bool {
        if folder.name == "Pods" {
            return !ignorePods
        }

        return true
    }
}
