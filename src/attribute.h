//
// Created by Rieon Ke on 2020/7/24.
//

#ifndef CJASM_ATTRIBUTE_H
#define CJASM_ATTRIBUTE_H

#include "def.h"
#include "util.h"
#include "mem_buf.h"

typedef struct cj_attribute_group_s cj_attribute_group_t;
struct cj_attribute_group_s {
    u2 count;
    u4 *heads;
    u4 *tails;
    cj_attribute_t **fetched;
};


cj_attribute_t *cj_attribute_new(enum cj_attr_type type);

/**
 * 根据属性名解析属性类型.
 * @param type_str 属性名
 * @return 属性类型
 */
enum cj_attr_type cj_attr_parse_type(const_str type_str);

const char *cj_attr_type_to_str(enum cj_attr_type type);

cj_mem_buf_t *cj_attribute_to_buf(cj_class_t *cls, cj_attribute_t *attr);

bool cj_attribute_group_add(cj_class_t *cls, cj_attribute_group_t *group, cj_attribute_t *attr);

cj_mem_buf_t *cj_attribute_group_to_buf(cj_class_t *cls, cj_attribute_group_t *group);

CJ_INTERNAL void cj_attribute_parse_offsets(buf_ptr ptr, u4 offset, u4 **offsets, u4 len);

CJ_INTERNAL cj_attribute_t *cj_attribute_group_get(cj_class_t *ctx, cj_attribute_group_t *set, u2 idx);

CJ_INTERNAL void cj_attribute_group_free(cj_attribute_group_t *set);

CJ_INTERNAL void cj_attribute_free(cj_attribute_t *attr);

u4 cj_attribute_get_head_offset(cj_attribute_t *attr);

void cj_attribute_set_data(cj_attribute_t *attr, void *data);

void cj_attribute_mark_dirty(cj_attribute_t *attr);

cj_attribute_group_t *cj_attribute_group_new(u2 count, u4 *heads, u4 *tails);

#endif //CJASM_ATTRIBUTE_H
