rule encodedBase64_vjw0rm_detection_rule {
meta:
    description = "Detects vjw0rm string encoded in base64"
    author = "Andres Nahuel Antola"
    date = "2019-10-29"
    hash = "3a7d372c4d53bb1ab91c7dd57e0234946a4fe303a5d17f3883006c0fa96a9959"

    strings:
        $vjw0rm = "vjw0rm" base64

    condition:
        $vjw0rm
}