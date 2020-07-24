//
// Created by Rieon Ke on 2020/7/23.
//

#ifndef CJASM_ANNOTATION_H
#define CJASM_ANNOTATION_H

#include <cjasm.h>
#include "util.h"

cj_annotation_t *cj_annotation_new();

CJ_INTERNAL cj_annotation_t *cj_annotation_parse(cj_class_t *ctx, buf_ptr attr_ptr, u4 *out_offset);

CJ_INTERNAL cj_element_t *cj_annotation_parse_element_value(cj_class_t *ctx, buf_ptr ev_ptr, u4 *out_offset);

CJ_INTERNAL void cj_annotation_free(cj_annotation_t *ann);

CJ_INTERNAL bool cj_annotation_group_init(cj_class_t *ctx, cj_attribute_group_t *attr_set, cj_annotation_group_t **set);

CJ_INTERNAL cj_annotation_t *cj_annotation_group_get(cj_class_t *ctx, cj_annotation_group_t *set, u2 idx);

CJ_INTERNAL void cj_annotation_group_free(cj_annotation_group_t *set);

#endif //CJASM_ANNOTATION_H
