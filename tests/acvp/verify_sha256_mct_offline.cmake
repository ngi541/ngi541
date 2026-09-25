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
        "SHA2-256 MCT request does not exist: "
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
        "SHA2-256 MCT offline runner failed (${runner_result})\n"
        "stdout:\n${runner_stdout}\n"
        "stderr:\n${runner_stderr}"
    )
endif()

if(NOT EXISTS "${NGI541_ACVP_RESPONSE}")
    message(
        FATAL_ERROR
        "SHA2-256 MCT response file was not created"
    )
endif()

file(
    READ
    "${NGI541_ACVP_RESPONSE}"
    response_json
)

string(
    JSON response_vs_id
    GET "${response_json}"
    1
    vsId
)

if(NOT response_vs_id EQUAL 9004)
    message(
        FATAL_ERROR
        "Unexpected SHA2-256 MCT vsId: ${response_vs_id}"
    )
endif()

string(
    JSON group_count
    LENGTH "${response_json}"
    1
    testGroups
)

if(NOT group_count EQUAL 1)
    message(
        FATAL_ERROR
        "Expected exactly one SHA2-256 MCT group, got "
        "${group_count}"
    )
endif()

string(
    JSON tc_id
    GET "${response_json}"
    1
    testGroups
    0
    tests
    0
    tcId
)

if(NOT tc_id EQUAL 130)
    message(
        FATAL_ERROR
        "Unexpected SHA2-256 MCT tcId: ${tc_id}"
    )
endif()

string(
    JSON result_count
    LENGTH "${response_json}"
    1
    testGroups
    0
    tests
    0
    resultsArray
)

if(NOT result_count EQUAL 100)
    message(
        FATAL_ERROR
        "Expected 100 SHA2-256 MCT results, got "
        "${result_count}"
    )
endif()


function(assert_md result_index expected)

    string(
        JSON actual
        GET "${response_json}"
        1
        testGroups
        0
        tests
        0
        resultsArray
        ${result_index}
        md
    )

    string(TOUPPER "${actual}" actual)
    string(TOUPPER "${expected}" expected_upper)

    if(NOT actual STREQUAL expected_upper)
        message(
            FATAL_ERROR
            "SHA2-256 MCT mismatch at outer=${result_index}\n"
            "expected: ${expected_upper}\n"
            "actual:   ${actual}"
        )
    endif()

endfunction()


assert_md(
    0
    "D1DA8BC89C6E5CE9E601024A0A0776FBC368430A07C3925252731C816F63CA11"
)

assert_md(
    49
    "C286A81DFB62C3D434C3BEEC47DF4D8638A51C5FF49A294A33975D0E70F0C470"
)

assert_md(
    99
    "F0A1E0061AD90C733E16B890B50584926D9513F47A0D193B2827B6DC093E3579"
)

message(
    STATUS
    "SHA2-256 ACVP MCT offline verification passed"
)