import swiftBeeCore


let tool = CommandLineTool(arguments: ["./", "search_cities_en.txt"])

do {
    try tool.run()
} catch {
    print("Whoops! An error occurred: \(error)")
}
