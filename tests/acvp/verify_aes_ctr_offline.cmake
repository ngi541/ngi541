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
        "NGI541 AES-CTR ACVP offline runner failed (${runner_result})\n"
        "stdout:\n${runner_stdout}\n"
        "stderr:\n${runner_stderr}"
    )
endif()

if(NOT EXISTS "${NGI541_ACVP_RESPONSE}")
    message(
        FATAL_ERROR
        "AES-CTR ACVP response file was not created"
    )
endif()

file(
    READ
    "${NGI541_ACVP_RESPONSE}"
    response_json
)

#
# Validate vector-set identity.
#
string(
    JSON response_vs_id
    GET "${response_json}"
    1
    vsId
)

if(NOT response_vs_id EQUAL 9002)
    message(
        FATAL_ERROR
        "Unexpected AES-CTR response vsId: ${response_vs_id}"
    )
endif()

#
# Validate test-case identity.
#
string(
    JSON response_tc_id
    GET "${response_json}"
    1
    testGroups
    0
    tests
    0
    tcId
)

if(NOT response_tc_id EQUAL 1)
    message(
        FATAL_ERROR
        "Unexpected AES-CTR tcId: ${response_tc_id}"
    )
endif()

#
# Validate CTR ciphertext.
#
string(
    JSON actual_ct
    GET "${response_json}"
    1
    testGroups
    0
    tests
    0
    ct
)

string(
    TOLOWER
    "${actual_ct}"
    actual_ct
)

string(
    CONCAT expected_ct
    "874d6191b620e3261bef6864990db6ce"
    "9806f66b7970fdff8617187bb9fffdff"
    "5ae4df3edbd5d35e5b4f09020db03eab"
    "1e031dda2fbe03d1792170a0f3009cee"
)

if(NOT actual_ct STREQUAL expected_ct)
    message(
        FATAL_ERROR
        "AES-CTR Counter Test ciphertext mismatch\n"
        "expected: ${expected_ct}\n"
        "actual:   ${actual_ct}"
    )
endif()

message(
    STATUS
    "AES-CTR offline ACVP Counter Test passed"
)