//
// Created by Rieon Ke on 2020/7/23.
//

#ifndef CJASM_ANNOTATION_H
#define CJASM_ANNOTATION_H

#include "def.h"

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

struct cj_element_pair_s {
    const_str name;
    cj_element_t *value;
};

struct cj_element_s {
    //@formatter:off
    u1 tag;

    /* const value { */
    u8 const_num;
    const_str const_str;
    /* }             */

    /* enum {        */
    const_str type_name;
    const_str const_name;
    /* }             */

    /* class         */
    u2 class_info_index;
    /* }             */

    /* annotation    */
    cj_annotation_t *annotation;
    /* }             */

    /* array         */
    u2 element_count;
    cj_element_t **elements;
    /* }             */
    //@formatter:on
};



cj_annotation_t *cj_annotation_new(const_str type, bool visible);

cj_annotation_group_t *cj_annotation_group_create(u2 count);

bool cj_annotation_add_kv(cj_annotation_t *ann, const_str key, const_str value);

bool cj_annotation_add_pair(cj_annotation_t *ann, cj_element_pair_t *pair);

bool cj_annotation_group_add(cj_class_t *cls, cj_annotation_group_t *group, cj_annotation_t *ann);

CJ_INTERNAL cj_annotation_t *cj_annotation_parse(cj_class_t *ctx, buf_ptr attr_ptr, u4 *out_offset);

CJ_INTERNAL cj_element_t *cj_annotation_parse_element_value(cj_class_t *ctx, buf_ptr ev_ptr, u4 *out_offset);

bool cj_annotation_group_write_buf(cj_class_t *cls, cj_annotation_group_t *group, bool visible, cj_mem_buf_t *buf);

bool cj_annotation_write_buf(cj_class_t *cls, cj_annotation_t *ann, cj_mem_buf_t *buf);

CJ_INTERNAL void cj_annotation_free(cj_annotation_t *ann);

CJ_INTERNAL bool cj_annotation_group_init(cj_class_t *ctx, cj_attribute_group_t *attr_set, cj_annotation_group_t **set);

bool cj_annotation_group_remove(cj_class_t *cls, cj_annotation_group_t *group, u2 index);

CJ_INTERNAL cj_annotation_t *cj_annotation_group_get(cj_class_t *ctx, cj_annotation_group_t *set, u2 idx);

CJ_INTERNAL void cj_annotation_group_free(cj_annotation_group_t *set);

#endif //CJASM_ANNOTATION_H
