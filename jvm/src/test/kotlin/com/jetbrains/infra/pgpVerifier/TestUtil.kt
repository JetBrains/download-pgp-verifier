package com.jetbrains.infra.pgpVerifier
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.time.Instant
import java.time.ZonedDateTime

object TestUtil {
    val testInstant: Instant = ZonedDateTime.parse("2021-09-24T20:26:22+00:00").toInstant()

    fun getTestDataFile(name: String): Path {
        val projectRoot = getProjectRootFromWorkingDirectory()
        val testDataFile = projectRoot.parent.resolve("data").resolve(name)
        if (Files.notExists(testDataFile)) {
            error("Test data file '$name' was not found at $testDataFile")
        }
        return testDataFile
    }

    fun getTestDataBytes(name: String): ByteArray = Files.readAllBytes(getTestDataFile(name))

    private fun getProjectRootFromWorkingDirectory(): Path {
        val workingDirectory = Paths.get(System.getProperty("user.dir"))

        var current = workingDirectory
        while (current.parent != null) {
            if (Files.exists(current.resolve("gradle.properties"))) {
                return current
            }
            current = current.parent
        }

        error("Project root was not found from current working directory $workingDirectory")
    }
}