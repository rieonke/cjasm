//
// Created by Rieon Ke on 2020/8/1.
//

#ifndef CJASM_CODE_H
#define CJASM_CODE_H

#include "def.h"

struct cj_code_s {
    u4 dirty;
    u4 head;
    u4 length;
    u2 max_stack;
    u2 max_locals;
    cj_method_t *method;
    cj_attribute_t *attr;
    cj_exception_tab_t *exception_tab;
    cj_attribute_group_t *attr_group;
    cj_line_number_tab_t *line_number_tab;
    cj_local_var_tab_t *local_var_tab;
    cj_local_var_type_tab_t *local_var_type_tab;
    cj_stack_map_tab_t *stack_map_tab;
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

struct cj_local_var_s {
    u2 start_pc;
    u2 length;
    u2 name_index;
    u2 descriptor_index;
    u2 index;
};

struct cj_local_var_tab_s {
    u2 length;
    cj_local_var_t **local_vars;
};

struct cj_local_var_type_s {
    u2 start_pc;
    u2 length;
    u2 name_index;
    u2 signature_index;
    u2 index;
};

struct cj_local_var_type_tab_s {
    u2 length;
    cj_local_var_type_t **types;
};

enum cj_stack_map_frame_type {
    CJ_SMFT_SAME,
    CJ_SMFT_SAME_LOCALS_1_STACK_ITEM,
    CJ_SMFT_SAME_LOCALS_1_STACK_ITEM_EXTENDED,
    CJ_SMFT_CHOP,
    CJ_SMFT_SAME_FRAME_EXTENDED,
    CJ_SMFT_APPEND,
    CJ_SMFT_FULL_FRAME
};

enum cj_veri_type {
    CJ_VT_ITEM_TOP = 0,
    CJ_VT_ITEM_INTEGER = 1,
    CJ_VT_ITEM_FLOAT = 2,
    CJ_VT_ITEM_DOUBLE = 3,
    CJ_VT_ITEM_LONG = 4,
    CJ_VT_ITEM_NULL = 5,
    CJ_VT_ITEM_UNINITIALIZED_THIS = 6,
    CJ_VT_ITEM_OBJECT = 7,
    CJ_VT_ITEM_UNINITIALIZED = 8
};

struct cj_stack_map_frame_s {
    u1 type;
    enum cj_stack_map_frame_type frame_type;
    u2 offset_delta;
    u2 veri_info_len;
    cj_veri_type_info_t **veri_infoes;
};

struct cj_veri_type_info_s {
    u1 type;
    u2 data;
};

struct cj_stack_map_tab_s {
    u2 length;
    cj_stack_map_frame_t **frames;
};

cj_code_t *cj_code_attr_parse(cj_method_t *method, cj_attribute_t *attr);

cj_exception_tab_t *cj_code_get_exception_table(cj_code_t *code);

cj_line_number_tab_t *cj_code_get_line_number_table(cj_code_t *code);

cj_local_var_tab_t *cj_code_get_local_var_table(cj_code_t *code);

cj_local_var_type_tab_t *cj_code_get_local_var_type_table(cj_code_t *code);

cj_stack_map_tab_t *cj_code_get_stack_map_table(cj_code_t *code);

u2 cj_code_get_attribute_count(cj_code_t *code);

cj_attribute_group_t *cj_code_get_attribute_group(cj_code_t *code);

bool cj_code_remove_stack_map_tab(cj_code_t *code);

bool cj_code_write_buf(cj_code_t *code, cj_mem_buf_t *buf);

void cj_code_free(cj_code_t *code);

void cj_code_mark_dirty(cj_code_t *code, u4 flags);

cj_stack_map_frame_t *cj_stack_map_frame_new();

#endif //CJASM_CODE_H
