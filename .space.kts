/**
* JetBrains Space Automation
* This Kotlin-script file lets you automate build activities
* For more info, see https://www.jetbrains.com/help/space/automation.html
*/

job("Build and run tests") {
    container("openjdk:11") {
        workDir = "jvm"
        kotlinScript { api ->
            api.gradlew("build")
        }
    }
}
