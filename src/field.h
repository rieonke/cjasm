//
// Created by Rieon Ke on 2020/7/23.
//

#ifndef CJASM_FIELD_H
#define CJASM_FIELD_H

#include "def.h"
#include "mem_buf.h"
#include "util.h"
#include "hashmap.h"
#include "annotation.h"


/**
 * 获取字段名.
 * 返回值不可被释放.
 * @param field cj 字段
 * @return 字段名，不可被释放.
 */
const_str cj_field_get_name(cj_field_t *field);

/**
 * 设置字段名.
 * @param field  字段.
 * @param name 名称.
 */
bool cj_field_set_name(cj_field_t *field, const_str name);

/**
 * 获取字段Access Flags.
 * @param field cj 字段
 * @return access flags
 */
cj_modifiers_t cj_field_get_modifiers(cj_field_t *field);

/**
 * 获取字段描述符.
 * 返回值不可被释放.
 * @param field 字段
 * @return 字段描述符，不可被释放.
 */
const_str cj_field_get_descriptor(cj_field_t *field);

/**
 * 获取字段的属性数量.
 * @param field 字段
 * @return 字段数量
 */
u2 cj_field_get_attribute_count(cj_field_t *field);

/**
 * 根据索引值获取字段的属性.
 * 返回值不可被释放.
 * @param field 字段
 * @param idx 索引值
 * @return 属性，当不存在该索引值时，返回NULL
 */
cj_attribute_t *cj_field_get_attribute(cj_field_t *field, u2 idx);

/**
 * 获取字段的注解数量.
 * @param field 字段
 * @return 注解数量
 */
u2 cj_field_get_annotation_count(cj_field_t *field);

/**
 * 根据索引值获取字段的注解.
 * 返回值不可被释放.
 * @param field 字段
 * @param idx 索引
 * @return 注解，当不存在该索引时，返回NULL
 */
cj_annotation_t *cj_field_get_annotation(cj_field_t *field, u2 idx);

/**
 * 向字段添加注解.
 * @param field
 * @param ann
 * @return
 */
bool cj_field_add_annotation(cj_field_t *field, cj_annotation_t *ann);


/**
 * 获取注解集合
 * 返回值不可被释放.
 * @param field
 * @return
 */
cj_annotation_group_t *cj_field_get_annotation_group(cj_field_t *field);

/**
 * 获取属性的集合.
 * 返回值不可被释放.
 * @param field
 * @return
 */
cj_attribute_group_t *cj_field_get_attribute_group(cj_field_t *field);


void cj_field_mark_removed(cj_field_t *field);

cj_field_group_t *cj_field_group_new(u2 count, u4 *offsets, u4 *tails);

bool cj_field_group_add(cj_class_t *ctx, cj_field_group_t *group, cj_field_t *field);

cj_field_t *cj_field_new(cj_class_t *ctx, u2 access_flags, const_str name, const_str descriptor);

cj_field_t *cj_field_group_get_by_name(cj_class_t *ctx, cj_field_group_t *set, const_str name);

cj_field_t *cj_field_group_get(cj_class_t *ctx, cj_field_group_t *set, u2 idx);

cj_mem_buf_t *cj_field_to_buf(cj_field_t *field);

void cj_field_set_free(cj_field_group_t *set);

CJ_INTERNAL void cj_field_free(cj_field_t *field);


#endif //CJASM_FIELD_H
