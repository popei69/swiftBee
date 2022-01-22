# swiftBee 🐝

Welcome to `swiftBee`🐝, a static code analyser to detect vulnerabilities and security issues in your iOS codebase but not only. It's focused on covering OWASP Top 10 security risks.

_The development is at an exploratory phase yo see how relevant and useful it can be to other developers, keeping your favorite app safer._

## How to use

Clone the repository, compile the code and run it against folder you want to analyse.

```
swift build -c release
.build/release/swiftBee {target_folder}
```

It will generate a `report.json` in your {target_folder} listing the detected issues as well as an overall score. 

```
{
    "averageCSVSS":7.5,
    "securityScore": 25,
    "lowCount":5,
    "mediumCount":86,
    "highCount":279,
    "criticalCount":0,
    "totalCount":372,
    "vulnerabilities": [ ... ]
}
```