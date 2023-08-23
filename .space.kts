/**
* JetBrains Space Automation
* This Kotlin-script file lets you automate build activities
* For more info, see https://www.jetbrains.com/help/space/automation.html
*/

job("Build and run tests") {
    container("openjdk:17-bullseye") {
        workDir = "jvm"
        kotlinScript { api ->
            api.gradlew("--info", "build")
        }
    }
}

job("Publish to maven repository") {
    startOn {
        gitPush {
            enabled = false
        }
    }

    container("openjdk:17-bullseye") {
        workDir = "jvm"

        env["INTELLIJ_DEPENDENCIES_PUBLICATION_CLIENT_ID"] = "{{ project:intellij-dependencies-publication-client-id }}"
        env["INTELLIJ_DEPENDENCIES_PUBLICATION_CLIENT_SECRET"] = "{{ project:intellij-dependencies-publication-client-secret }}"

        kotlinScript { api ->
            api.gradlew("--info", "publish")
        }
    }
}