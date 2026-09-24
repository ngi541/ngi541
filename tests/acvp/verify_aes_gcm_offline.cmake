if(
    NOT DEFINED NGI541_ACVP_RUNNER
    OR NGI541_ACVP_RUNNER STREQUAL ""
)
    message(
        FATAL_ERROR
        "NGI541_ACVP_RUNNER is not defined or empty"
    )
endif()

if(
    NOT DEFINED NGI541_ACVP_REQUEST
    OR NGI541_ACVP_REQUEST STREQUAL ""
)
    message(
        FATAL_ERROR
        "NGI541_ACVP_REQUEST is not defined or empty"
    )
endif()

if(
    NOT DEFINED NGI541_ACVP_RESPONSE
    OR NGI541_ACVP_RESPONSE STREQUAL ""
)
    message(
        FATAL_ERROR
        "NGI541_ACVP_RESPONSE is not defined or empty"
    )
endif()

if(NOT EXISTS "${NGI541_ACVP_RUNNER}")
    message(
        FATAL_ERROR
        "NGI541 ACVP runner does not exist: "
        "${NGI541_ACVP_RUNNER}"
    )
endif()

if(NOT EXISTS "${NGI541_ACVP_REQUEST}")
    message(
        FATAL_ERROR
        "ACVP request file does not exist: "
        "${NGI541_ACVP_REQUEST}"
    )
endif()

file(REMOVE "${NGI541_ACVP_RESPONSE}")

execute_process(
    COMMAND
        "${NGI541_ACVP_RUNNER}"
        "${NGI541_ACVP_REQUEST}"
        "${NGI541_ACVP_RESPONSE}"

    RESULT_VARIABLE runner_result
    OUTPUT_VARIABLE runner_stdout
    ERROR_VARIABLE runner_stderr
)

if(NOT runner_result EQUAL 0)
    message(
        FATAL_ERROR
        "NGI541 ACVP offline runner failed (${runner_result})\n"
        "stdout:\n${runner_stdout}\n"
        "stderr:\n${runner_stderr}"
    )
endif()

if(NOT EXISTS "${NGI541_ACVP_RESPONSE}")
    message(
        FATAL_ERROR
        "ACVP response file was not created"
    )
endif()

file(
    READ
    "${NGI541_ACVP_RESPONSE}"
    response_json
)

#
# Validate response vector-set identity.
#
string(
    JSON response_vs_id
    GET "${response_json}"
    1
    vsId
)

if(NOT response_vs_id EQUAL 9001)
    message(
        FATAL_ERROR
        "Unexpected ACVP response vsId: ${response_vs_id}"
    )
endif()

#
# Encrypt response.
#
string(
    JSON encrypt_tc_id
    GET "${response_json}"
    1
    testGroups
    0
    tests
    0
    tcId
)

if(NOT encrypt_tc_id EQUAL 1)
    message(
        FATAL_ERROR
        "Unexpected AES-GCM encrypt tcId"
    )
endif()

string(
    JSON encrypt_ct
    GET "${response_json}"
    1
    testGroups
    0
    tests
    0
    ct
)

string(
    JSON encrypt_tag
    GET "${response_json}"
    1
    testGroups
    0
    tests
    0
    tag
)

string(TOLOWER "${encrypt_ct}" encrypt_ct)
string(TOLOWER "${encrypt_tag}" encrypt_tag)

set(
    expected_ct
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
)

set(
    expected_tag
    "5bc94fbc3221a5db94fae95ae7121a47"
)

if(NOT encrypt_ct STREQUAL expected_ct)
    message(
        FATAL_ERROR
        "AES-GCM offline encrypt ciphertext mismatch\n"
        "expected: ${expected_ct}\n"
        "actual:   ${encrypt_ct}"
    )
endif()

if(NOT encrypt_tag STREQUAL expected_tag)
    message(
        FATAL_ERROR
        "AES-GCM offline encrypt tag mismatch\n"
        "expected: ${expected_tag}\n"
        "actual:   ${encrypt_tag}"
    )
endif()

#
# Successful decrypt response.
#
string(
    JSON decrypt_tc_id
    GET "${response_json}"
    1
    testGroups
    1
    tests
    0
    tcId
)

if(NOT decrypt_tc_id EQUAL 2)
    message(
        FATAL_ERROR
        "Unexpected AES-GCM decrypt tcId"
    )
endif()

string(
    JSON decrypt_passed
    GET "${response_json}"
    1
    testGroups
    1
    tests
    0
    testPassed
)

if(NOT decrypt_passed)
    message(
        FATAL_ERROR
        "Valid AES-GCM decrypt was reported as failed"
    )
endif()

string(
    JSON decrypt_pt
    GET "${response_json}"
    1
    testGroups
    1
    tests
    0
    pt
)

string(TOLOWER "${decrypt_pt}" decrypt_pt)

set(
    expected_pt
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
)

if(NOT decrypt_pt STREQUAL expected_pt)
    message(
        FATAL_ERROR
        "AES-GCM offline decrypt plaintext mismatch\n"
        "expected: ${expected_pt}\n"
        "actual:   ${decrypt_pt}"
    )
endif()

#
# Authentication-failure response.
#
string(
    JSON rejected_tc_id
    GET "${response_json}"
    1
    testGroups
    1
    tests
    1
    tcId
)

if(NOT rejected_tc_id EQUAL 3)
    message(
        FATAL_ERROR
        "Unexpected AES-GCM rejected decrypt tcId"
    )
endif()

string(
    JSON rejected_passed
    GET "${response_json}"
    1
    testGroups
    1
    tests
    1
    testPassed
)

if(rejected_passed)
    message(
        FATAL_ERROR
        "Invalid AES-GCM tag was incorrectly accepted"
    )
endif()

message(
    STATUS
    "AES-GCM offline ACVP vector processing passed"
)