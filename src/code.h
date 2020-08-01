//
// Created by Rieon Ke on 2020/8/1.
//

#ifndef CJASM_CODE_H
#define CJASM_CODE_H

#include "def.h"

struct cj_code_s {
    u4 head;
    u4 length;
    u2 max_stack;
    u2 max_locals;
    cj_method_t *method;
    cj_attribute_t *attr;
    cj_exception_tab_t *exception_tab;
    cj_attribute_group_t *attr_group;
    cj_line_number_tab_t *line_number_tab;
};

struct cj_line_number_s {
    u2 start_pc;
    u2 number;
};

struct cj_line_number_tab_s {
    u2 length;
    cj_line_number_t **line_numbers;
};

struct cj_exception_tab_s {
    u2 length;
    cj_exception_t **exceptions;
};

struct cj_exception_s {
    u2 start_pc;
    u2 end_pc;
    u2 handler_pc;
    u2 catch_type;
};

cj_code_t *cj_code_attr_parse(cj_method_t *method, cj_attribute_t *attr);

cj_exception_tab_t *cj_code_get_exception_table(cj_code_t *code);

cj_line_number_tab_t *cj_code_get_line_number_table(cj_code_t *code);

u2 cj_code_get_attribute_count(cj_code_t *code);

cj_attribute_group_t *cj_code_get_attribute_group(cj_code_t *code);

void cj_code_free(cj_code_t *code);

#endif //CJASM_CODE_H
