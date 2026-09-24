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
# Validate vector-set identity.
#
string(
    JSON response_vs_id
    GET "${response_json}"
    1
    vsId
)

if(NOT response_vs_id EQUAL 9003)
    message(
        FATAL_ERROR
        "Unexpected SHA-224 ACVP response vsId: "
        "${response_vs_id}"
    )
endif()

#
# SHA-224("abc").
#
string(
    JSON abc_tc_id
    GET "${response_json}"
    1
    testGroups
    0
    tests
    0
    tcId
)

if(NOT abc_tc_id EQUAL 1)
    message(
        FATAL_ERROR
        "Unexpected SHA-224 abc tcId"
    )
endif()

string(
    JSON abc_md
    GET "${response_json}"
    1
    testGroups
    0
    tests
    0
    md
)

string(TOLOWER "${abc_md}" abc_md)

set(
    expected_abc_md
    "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
)

if(NOT abc_md STREQUAL expected_abc_md)
    message(
        FATAL_ERROR
        "SHA-224 abc digest mismatch\n"
        "expected: ${expected_abc_md}\n"
        "actual:   ${abc_md}"
    )
endif()

message(
    STATUS
    "SHA-224 offline ACVP vector processing passed"
)