//
// Created by Rieon Ke on 2020/7/9.
//
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cjasm.h"
#include "../src/util.h"
#include <setjmp.h>
#include <cmocka.h>


#define TEST_CLASS "io/ticup/example/Test.class"
#define MAJOR_VERSION 52
#define MINOR_VERSION 0
#define INIT_IDX 29

#define CTX ((cj_class_t*)*state)

static int setup(void **state) {

    unsigned char *buf = NULL;
    long len = cj_load_file(TEST_CLASS, &buf);
    assert(len > 0);
    assert_non_null(buf);

    *state = cj_class_new(buf, len);

    free(buf);

    assert_non_null(state);
    return 0;
}

static int teardown(void **state) {
    cj_class_free(CTX);
    return 0;
}

void test_check_version(void **state) {
    assert_int_equal(CTX->major_version, MAJOR_VERSION);
    assert_int_equal(CTX->minor_version, MINOR_VERSION);
}

void test_check_access_flags(void **state) {
    assert_int_equal(CTX->access_flags, 0x21);
}

void test_check_class_name(void **state) {
    const unsigned char *name = cj_class_get_name(CTX);
    assert_string_equal(name, "io/ticup/example/Test");
}

void test_check_field(void **state) {

    cj_field_t *field = cj_class_get_field(CTX, 0);

    const unsigned char *name = cj_field_get_name(field);
    assert_string_equal(name, "name");

    cj_field_set_name(field, "hello");

    assert_string_equal(cj_field_get_name(field), "hello");

    const unsigned char *desc = cj_field_get_descriptor(field);
    assert_string_equal(desc, "Ljava/lang/String;");

    const unsigned char *str = cj_cp_get_str(CTX, priv(CTX)->cp_len);
    assert_string_equal(str, "hello");

}

void test_get_str(void **ctx) {

    const unsigned char *str = cj_cp_get_str(*ctx, INIT_IDX);
    const unsigned char *str1 = cj_cp_get_str(*ctx, INIT_IDX);

    assert_non_null(str);
    assert_string_equal(str, "<init>");

    assert_ptr_equal(str, str1);
    assert_non_null(str1);
    assert_string_equal(str1, "<init>");

}


int main(void) {

    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_check_access_flags),
            cmocka_unit_test(test_check_class_name),
            cmocka_unit_test(test_check_version),
            cmocka_unit_test(test_check_field),
            cmocka_unit_test(test_get_str),
    };

    return cmocka_run_group_tests(tests, setup, teardown);
}