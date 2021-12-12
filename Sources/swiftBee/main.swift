import swiftBeeCore


let tool = CommandLineTool(arguments: ["./", "~/development/swift/JapanExpress"])

do {
    try tool.run()
} catch {
    print("Whoops! An error occurred: \(error)")
}
