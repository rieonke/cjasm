//
// Created by Rieon Ke on 2020/7/23.
//

#ifndef CJASM_ANNOTATION_H
#define CJASM_ANNOTATION_H

#include "def.h"
#include "util.h"
#include "mem_buf.h"

typedef struct cj_annotation_group_s cj_annotation_group_t;

struct cj_annotation_group_s {
    u2 count;
    u4 *offsets;
    cj_annotation_t **cache;
    cj_attribute_t *in_attr; //todo 父级不可见注解属性，换个名字
    cj_attribute_t *vi_attr; //todo 父级可见注解属性，换个名字
};

struct cj_annotation_s {
    const_str type_name;
    bool visible;
    u2 attributes_count;
    cj_element_pair_t **attributes;
    cj_pointer priv;
};

cj_annotation_t *cj_annotation_new(const_str type, bool visible);

bool cj_annotation_group_add(cj_class_t *cls, cj_annotation_group_t *group, cj_annotation_t *ann);

CJ_INTERNAL cj_annotation_t *cj_annotation_parse(cj_class_t *ctx, buf_ptr attr_ptr, u4 *out_offset);

CJ_INTERNAL cj_element_t *cj_annotation_parse_element_value(cj_class_t *ctx, buf_ptr ev_ptr, u4 *out_offset);

CJ_INTERNAL void cj_annotation_free(cj_annotation_t *ann);

CJ_INTERNAL bool cj_annotation_group_init(cj_class_t *ctx, cj_attribute_group_t *attr_set, cj_annotation_group_t **set);

CJ_INTERNAL cj_annotation_t *cj_annotation_group_get(cj_class_t *ctx, cj_annotation_group_t *set, u2 idx);

CJ_INTERNAL void cj_annotation_group_free(cj_annotation_group_t *set);

cj_mem_buf_t *cj_annotation_group_to_buf(cj_class_t *cls, cj_annotation_group_t *group, bool visible);

cj_mem_buf_t *cj_annotation_to_buf(cj_class_t *cls, cj_annotation_t *ann);

#endif //CJASM_ANNOTATION_H
