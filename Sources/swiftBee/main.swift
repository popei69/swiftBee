import swiftBeeCore


let tool = CommandLineTool(arguments: ["./", "~/development/swift/sardine-fomo"])

do {
    try tool.run()
} catch {
    print("Whoops! An error occurred: \(error)")
}
