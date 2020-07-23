cmake_minimum_required(VERSION 3.0)
project(cjasm C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -pedantic -pedantic-errors")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DCJ_DEBUG")

include(third_party/ThirdParty.cmake)

include_directories(include)

add_library(cjasm-object OBJECT include/cjasm.h src/cjasm.c src/util.h src/util.c src/method.c src/class.c src/cpool.c src/cpool.h src/descriptor.c src/descriptor.h src/mem_buf.c src/mem_buf.h)
add_library(cjasm-shared SHARED $<TARGET_OBJECTS:cjasm-object>)
add_library(cjasm-static STATIC $<TARGET_OBJECTS:cjasm-object>)

set_target_properties(cjasm-object PROPERTIES POSITION_INDEPENDENT_CODE 1)
set_target_properties(cjasm-static PROPERTIES OUTPUT_NAME cjasm)
set_target_properties(cjasm-shared PROPERTIES OUTPUT_NAME cjasm)

find_package(Java REQUIRED)
include(UseJava)

set(CMAKE_JAVA_COMPILE_FLAGS "-encoding" "UTF8" "-source" "1.8" "-target" "1.8")

add_jar(test_java_jar test/resources/Test.java
        OUTPUT_NAME Test
        ENTRY_POINT Test)

add_custom_command(
        TARGET test_java_jar POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/io/
        COMMAND ${CMAKE_COMMAND} -E tar xzf ${CMAKE_BINARY_DIR}/Test.jar
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        DEPENDS ${CMAKE_BINARY_DIR}/Test.jar
        COMMENT "Unpacking Test.jar"
        VERBATIM
)

function(cjasm_add_ctest name)
    add_executable(test_${name} test/${name}.c)
    target_link_libraries(test_${name} cjasm-static cmocka)
    add_dependencies(test_${name} cjasm-static libcmocka test_java_jar)
    add_test(NAME test_${name} COMMAND test_${name})
endfunction()

enable_testing()
cjasm_add_ctest(load_bytecode)
cjasm_add_ctest(simple_decompiler)
cjasm_add_ctest(write_bytecode)

