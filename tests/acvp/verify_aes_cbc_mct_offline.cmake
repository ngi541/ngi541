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
        "AES-CBC MCT request does not exist: "
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
        "AES-CBC MCT offline runner failed (${runner_result})\n"
        "stdout:\n${runner_stdout}\n"
        "stderr:\n${runner_stderr}"
    )
endif()

if(NOT EXISTS "${NGI541_ACVP_RESPONSE}")
    message(
        FATAL_ERROR
        "AES-CBC MCT response file was not created"
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

if(NOT response_vs_id EQUAL 9003)
    message(
        FATAL_ERROR
        "Unexpected AES-CBC MCT vsId: ${response_vs_id}"
    )
endif()

string(
    JSON group_count
    LENGTH "${response_json}"
    1
    testGroups
)

if(NOT group_count EQUAL 6)
    message(
        FATAL_ERROR
        "Expected 6 AES-CBC MCT groups, got ${group_count}"
    )
endif()


function(assert_json_value
    group_index
    result_index
    field
    expected)

    string(
        JSON actual
        GET "${response_json}"
        1
        testGroups
        ${group_index}
        tests
        0
        resultsArray
        ${result_index}
        ${field}
    )

    string(TOUPPER "${actual}" actual)
    string(TOUPPER "${expected}" expected_upper)

    if(NOT actual STREQUAL expected_upper)
        message(
            FATAL_ERROR
            "AES-CBC MCT mismatch: "
            "group=${group_index}, "
            "result=${result_index}, "
            "field=${field}\n"
            "expected: ${expected_upper}\n"
            "actual:   ${actual}"
        )
    endif()

endfunction()


function(assert_mct_group
    group_index
    expected_tc_id)

    string(
        JSON tc_id
        GET "${response_json}"
        1
        testGroups
        ${group_index}
        tests
        0
        tcId
    )

    if(NOT tc_id EQUAL expected_tc_id)
        message(
            FATAL_ERROR
            "Unexpected tcId in group ${group_index}: "
            "${tc_id}"
        )
    endif()

    string(
        JSON result_count
        LENGTH "${response_json}"
        1
        testGroups
        ${group_index}
        tests
        0
        resultsArray
    )

    if(NOT result_count EQUAL 100)
        message(
            FATAL_ERROR
            "AES-CBC MCT tcId=${expected_tc_id}: "
            "expected 100 results, got ${result_count}"
        )
    endif()

endfunction()


#
# Structural validation.
#
assert_mct_group(0 2139)
assert_mct_group(1 2140)
assert_mct_group(2 2141)
assert_mct_group(3 2142)
assert_mct_group(4 2143)
assert_mct_group(5 2144)


#
# AES-CBC encrypt / 128-bit
#
assert_json_value(
    0 0 key
    "BFDCEBD27C5FBF998ABF0208745E9D7C"
)
assert_json_value(
    0 0 iv
    "BEFDA6FE9B5081A2EE6C0DCA0A3F2EF4"
)
assert_json_value(
    0 0 pt
    "6B3E19AB35F09D1CBC6F9AC43E167354"
)
assert_json_value(
    0 0 ct
    "03DD4D28FEFFE57ACFE63C702EB54453"
)

assert_json_value(
    0 49 key
    "617FABB7A945184F8FA2FAAA16D651FE"
)
assert_json_value(
    0 49 iv
    "4D47CC56BE2E7CA84A4C3D90EBF889E0"
)
assert_json_value(
    0 49 pt
    "9F81E9A7F2F1CC45E0143AE570D0B67D"
)
assert_json_value(
    0 49 ct
    "70B88A399B251569D27E5C3D2F08757B"
)

assert_json_value(
    0 99 key
    "9B8921CE4F6935480D937C4BA39DC722"
)
assert_json_value(
    0 99 iv
    "ED7336C078DB062D92028E2728B9B7EA"
)
assert_json_value(
    0 99 pt
    "87D4EBC0734E9B0B15B95FD6F313EE3E"
)
assert_json_value(
    0 99 ct
    "B415B2784F76EE00633BA591B6F966F0"
)


#
# AES-CBC encrypt / 192-bit
#
assert_json_value(
    1 0 key
    "1B370DDA66C0F3817FDE89126B57A12DE1F9BF8F8B4690A4"
)
assert_json_value(
    1 0 ct
    "601E0F799A9C841A87DF32E621C63861"
)

assert_json_value(
    1 49 key
    "F029D4B4FB799B848181E5CDBC89F0D632DFE46956167815"
)
assert_json_value(
    1 49 iv
    "6597733357A59426D8A67F919F6B80AE"
)
assert_json_value(
    1 49 pt
    "40A17AE5BDD303E2040C75E956A653A2"
)
assert_json_value(
    1 49 ct
    "28392AB80DBE4ADF5F46FEA92C622BB3"
)

assert_json_value(
    1 99 key
    "92D66095A20E0C5F87E29DD0D91E0C009AAE1AABB46512C5"
)
assert_json_value(
    1 99 iv
    "D029271C8954DD30D897AD9A0A01EA23"
)
assert_json_value(
    1 99 pt
    "29CA3B5AD99ABFD801A2CD831E266B66"
)
assert_json_value(
    1 99 ct
    "277B9F3CFA0679A5017888FED46E3B4E"
)


#
# AES-CBC encrypt / 256-bit
#
assert_json_value(
    2 0 key
    "CDFD53DA3739E846573A4F6CAAF4C418CEABC4F7D8E82A92C9B7EAF06ADA2A59"
)
assert_json_value(
    2 0 ct
    "ACE931509CC6329A78C21FCFBA59E4D4"
)

assert_json_value(
    2 49 key
    "9BB28B13ECF370E04A639B9C91CFF6ED3ACCE67F05A3B519A61BA03C7CFF866B"
)
assert_json_value(
    2 49 iv
    "744D752BF464EAF42055D7C8F5B4D48C"
)
assert_json_value(
    2 49 pt
    "0C409AB5EDF621121AA0B374ADC4733B"
)
assert_json_value(
    2 49 ct
    "2CE4539904F476FE3E75D6864AFB55C0"
)

assert_json_value(
    2 99 key
    "95876FFCA7993E2494700DBECB7109830835D8AF4603E895485B842033C71EFC"
)
assert_json_value(
    2 99 iv
    "2791470F411C97CDB0B2B39F1A9FC493"
)
assert_json_value(
    2 99 pt
    "F299F02D2171BD29A58E307C4AE0CB30"
)
assert_json_value(
    2 99 ct
    "F793ACE8AC7E66ECB257976A334872C4"
)


#
# AES-CBC decrypt / 128-bit
#
assert_json_value(
    3 0 key
    "40E883F994326CB8A8F50203FC7A1B2C"
)
assert_json_value(
    3 0 pt
    "B21A6B31AFBA19722C7ABDE5C364774A"
)

assert_json_value(
    3 49 key
    "98549C7D63268491D1EC29C857043A16"
)
assert_json_value(
    3 49 iv
    "41D15F90E872C56EDEB0A8AEC877ECD7"
)
assert_json_value(
    3 49 ct
    "0ABBC7EA21AF3DFD8E834D8AEC38A18E"
)
assert_json_value(
    3 49 pt
    "5506822B4EF1055F2EE0B73FB5977E82"
)

assert_json_value(
    3 99 key
    "A34350092872615571A44C9266E131E7"
)
assert_json_value(
    3 99 iv
    "4B122ED83752E99D32776FB576F44168"
)
assert_json_value(
    3 99 ct
    "D28E3D4197646A26326A9C2F99DA9DA3"
)
assert_json_value(
    3 99 pt
    "AC970E8A00AEDE70C98C9AE4EE09188E"
)


#
# AES-CBC decrypt / 192-bit
#
assert_json_value(
    4 0 key
    "08B594F8E3AA3B95B45BA04A4D2B4D0E998CCE8F8A0DE39A"
)
assert_json_value(
    4 0 pt
    "AC2915ECBA90BEE1B0D809189F3888B7"
)

assert_json_value(
    4 49 key
    "0F9D4F9D43535F88B9434ED830202A79FF8AC5D46813EA95"
)
assert_json_value(
    4 49 iv
    "F1C0F76D9ACE3E8CD62EC41354A864C0"
)
assert_json_value(
    4 49 ct
    "FD2F5FCC8D08D6862DA31B1EA50FA1A1"
)
assert_json_value(
    4 49 pt
    "1828A45D75B36EE21877B9D2E6EB72C5"
)

assert_json_value(
    4 99 key
    "A26007ABF62E3C708FED2ACC26A17ADA5B5E7D3A3EF042CD"
)
assert_json_value(
    4 99 iv
    "8BDA6E2E9505363E58C0850B11447F63"
)
assert_json_value(
    4 99 ct
    "E98BCFADE077313866C7F7B57CD1DC03"
)
assert_json_value(
    4 99 pt
    "149A73E9747871613519361C36ED6C1E"
)


#
# AES-CBC decrypt / 256-bit
#
assert_json_value(
    5 0 key
    "784F6CFAE31A34B45741774E06598FD348BEF3E500A7F01D55B8D475E271052D"
)
assert_json_value(
    5 0 pt
    "F819D445240C7A938FF3F1EBAF3A9457"
)

assert_json_value(
    5 49 key
    "85C3536A1967BAEFB8B7ADC90654308C756BB76A786F43EBF837B4C31A7531A8"
)
assert_json_value(
    5 49 iv
    "9847002531636983E2F487FBB6647DDC"
)
assert_json_value(
    5 49 ct
    "B719B598F68C062E80CAB0E2B373D1C2"
)
assert_json_value(
    5 49 pt
    "591C42154CC993E6F6FCB0E676E70915"
)

assert_json_value(
    5 99 key
    "C616202F92A8DFD41D28EAAA6436F1B94DD8558FC77FE5BE21BC9AB0EAF03DF8"
)
assert_json_value(
    5 99 iv
    "5657FF722B6F048E830DA7DBB22AEC77"
)
assert_json_value(
    5 99 ct
    "57435A335CA9FBBEE2FF475BEE625A41"
)
assert_json_value(
    5 99 pt
    "D6ED556DEECB04767366B62991C9A3BC"
)

message(
    STATUS
    "AES-CBC ACVP MCT offline verification passed"
)