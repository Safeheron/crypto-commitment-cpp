find_package(GTest REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

include_directories("../src")
include_directories(${GTEST_INCLUDE_DIRS})

add_executable(commitment-test commitment-test.cpp)
target_link_libraries(commitment-test
        CryptoCommitment
        ${GTEST_BOTH_LIBRARIES}
        pthread )
add_test(NAME commitment-test COMMAND commitment-test)


