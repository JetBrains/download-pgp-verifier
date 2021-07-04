package com.jetbrains.infra.pgpVerifier

object JetBrainsPgpConstants {
    // download@jetbrains.com key
    internal val JETBRAINS_DOWNLOADS_PGP_MASTER_PUBLIC_KEY = """
      -----BEGIN PGP PUBLIC KEY BLOCK-----
      
      mQGNBGBP58sBDADYRZmxLOkqrz0QZ/yESRpv7IeHGLqDE1a8QfFtFb14MJCLSAAS
      3nMD6Szi9mEjEqYdJURRcMjbUBhePgbhzGa3FYkjAB8lj6IKbu+ogCwVm1S8+caZ
      C6HNP1CIefa1wQgi/6FNWEBKbKefUr/DoG1fBAWUvTPC2BjiYOHDaU1xFWwhF3Np
      p0gEoK2KNgGgy/aSCi9Rb1M1ynPF7CcY8vKpAo6YfJpoNnput3t5FoF0uPnIac0F
      gikw6Iz8knUoYeqW2MTKNBxgQrtS+Ji1J0EgzT2Nq1SBMPfmq4/h1+XOQweWY/NR
      GNQTzcR3v+FkLkqCIaywcWUMXkhFXB8U3TdPa4bCEbFlP/AUkEw0X/obxm0isshU
      w7MRMPoBXR3FkEApkxB+bFptY3ZbBYhu5PCf4FWBE8+FkYEJ31IS+nABC2u9Jcav
      o5TqVd0y4e8VZ2qz18ez3j2G+nVthHz2OZ3AdEmq60K6iD57RY0H8zQK7xeEe3Ye
      VoRmpZdS8Eyk2aEAEQEAAbQhRG93bmxvYWQgPGRvd25sb2FkQGpldGJyYWlucy5j
      b20+iQHUBBMBCgA+AhsBBQsJCAcDBRUKCQgLBRYCAwEAAh4BAheAFiEEtG3HHgP+
      63+J0fJJH3qPh7nY9QEFAmBQ+RIFCQlnEscACgkQH3qPh7nY9QEwcQwA03ycUi3u
      IiKMqSPJBj6hYG2PFXHodMLr6naZe1g6i+pZGftB40frpMl9d4uX1HISi2HzwH1I
      NO8Ii+xhTk5uhECzRLkI+XXT4jTN3qNw1xmh034pUy+YqtflxGudMHjbhxMH19oR
      m1gf0Nto3CVd4rqYaiI9bZqr04zkzUFewK8YWHoL+hnWl33iKx5gvWfvhyVknSnx
      62bvtY0XZxpsfvQzas/KjL8VKnBTRewgtxtRYHpIuAwm+8E5R7HQUS3lf/HY9UEf
      dmJRpEAZIODLO7F83TlE/6SPtUwtwjIx1Owan4zLqDS2Qb+SV3jMEXoR/3MCNbLf
      wc2GMjSG3soeZ7prhzjIvgyW/2wpkZyZLqBevnsvmuDl+RpEQfSPfZLoTo0trDAm
      4alV5ophiZLOdPD5d6wbrw505NdRZ2a8pCPV/UhRm7A1AhPfElobSOKtyW5TiXvz
      pdJa9DG15eF4freZ+OPpo0epL8BBZ0tKu9Xi45My+Tss3Udwywks57GJiQGzBBAB
      CgAdFiEEvawfF9kxnqb4ihZ5Yahr/e7qo0UFAmBQ+ecACgkQYahr/e7qo0UJWwwA
      jkeDWvruJj6AJd6/2Glb59sd4H2abFo8DF61CIbzgURxZcGrbYZJC9RhKvHxXlW3
      GINZ933uVARNnnsrbSkhoSHiQS+hEz2Y+TqB/5bgcz7QDRvJmxWUxl/Jre47h+DM
      eACxDZzc2NwW6Q9XCwUzvlEfl4/Ibp1i3drPGW1Em6wr56vkhoRanTBzObFIOdE6
      X23rom22JxGiLik70nrQmUpLor9sBKwCHj9TKOeiRTEhAerzWgFZpgTgVFflgCoq
      c42aML5g0cE8hEDfHE4wm+55cT7hzjsCfetj4xN6g3t1M4d2m3XsZeBdQtX2M0Ng
      fBquptMN4TcKjrh/pIYGdyjpxHiJvXAr0XW6j8hYpqwzkstbcaeuIzSZKxmD/mEp
      pZzOL4V9tPsdsfjOTyDjbi8piywq35AujYO/gc/et/ewiwm1VqfLEkp52wuNuGRC
      ojRoIUIthHojE6JNnvaNuuP9Tu9t72uv/+tTWoYIesykhA1t258hlCwZ7u69d0NZ
      =OQv6
      -----END PGP PUBLIC KEY BLOCK-----
    """.trimIndent()

    val JETBRAINS_DOWNLOADS_PGP_SUB_KEYS_URL = "https://download.jetbrains.com/KEYS"
}
