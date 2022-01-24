//
//  Scanner.swift
//  
//
//  Created by Benoit PASQUIER on 12/12/2021.
//

import Files

final class Scanner {
    
    var exclusionFiles = [".gitignore"] 
    
    func scan(_ folder: Folder) -> [File] {
        
        var files = folder.files
            .filter { !exclusionFiles.contains($0.name) }
        
        for subfolder in folder.subfolders {
            files.append(contentsOf: scan(subfolder))
        }
        
        return files
    }
}
