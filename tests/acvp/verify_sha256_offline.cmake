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
# Vector-set identity.
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
        "Unexpected SHA-256 ACVP response vsId: "
        "${response_vs_id}"
    )
endif()

#
# Test case 1: SHA-256(empty message).
#
string(
    JSON empty_tc_id
    GET "${response_json}"
    1
    testGroups
    0
    tests
    0
    tcId
)

if(NOT empty_tc_id EQUAL 1)
    message(
        FATAL_ERROR
        "Unexpected SHA-256 empty-message tcId"
    )
endif()

string(
    JSON empty_md
    GET "${response_json}"
    1
    testGroups
    0
    tests
    0
    md
)

string(TOLOWER "${empty_md}" empty_md)

set(
    expected_empty_md
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

if(NOT empty_md STREQUAL expected_empty_md)
    message(
        FATAL_ERROR
        "SHA-256 empty-message digest mismatch\n"
        "expected: ${expected_empty_md}\n"
        "actual:   ${empty_md}"
    )
endif()

#
# Test case 2: SHA-256("abc").
#
string(
    JSON abc_tc_id
    GET "${response_json}"
    1
    testGroups
    0
    tests
    1
    tcId
)

if(NOT abc_tc_id EQUAL 2)
    message(
        FATAL_ERROR
        "Unexpected SHA-256 abc tcId"
    )
endif()

string(
    JSON abc_md
    GET "${response_json}"
    1
    testGroups
    0
    tests
    1
    md
)

string(TOLOWER "${abc_md}" abc_md)

set(
    expected_abc_md
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
)

if(NOT abc_md STREQUAL expected_abc_md)
    message(
        FATAL_ERROR
        "SHA-256 abc digest mismatch\n"
        "expected: ${expected_abc_md}\n"
        "actual:   ${abc_md}"
    )
endif()

message(
    STATUS
    "SHA-256 offline ACVP vector processing passed"
)