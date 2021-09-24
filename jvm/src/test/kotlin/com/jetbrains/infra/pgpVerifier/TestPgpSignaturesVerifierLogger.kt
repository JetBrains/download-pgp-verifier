package com.jetbrains.infra.pgpVerifier

object TestPgpSignaturesVerifierLogger : PgpSignaturesVerifierLogger {
    override fun info(message: String) {
        println(message)
    }
}