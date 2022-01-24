//
//  File.swift
//  
//
//  Created by Benoit Pasquier on 12/1/22.
//

import Foundation

extension Rule {
    var hasNotAnd: Bool {
        return regexNotAnd?.isEmpty == false
    }
    
    var hasNotOr: Bool {
        return regexNotOr?.isEmpty == false
    }
    
    var hasAnd: Bool {
        return regexAnd?.isEmpty == false
    }
    
    var hasOr: Bool {
        return regexOr?.isEmpty == false
    }
    
    var isMatch: Bool {
        return regexExactMatch?.isEmpty == false
    }
}
