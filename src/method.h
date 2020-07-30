//
// Created by Rieon Ke on 2020/7/24.
//

#ifndef CJASM_METHOD_H
#define CJASM_METHOD_H

#include "util.h"

typedef struct cj_method_group_s cj_method_group_t;
struct cj_method_group_s {
    u2 index;
    u2 count;
    u4 *heads;
    u4 *tails;
    cj_method_t **fetched;
};

/**
 * 获取方法名.
 * 返回值不可被释放.
 * @param method 方法
 * @return 方法名
 */
const_str cj_method_get_name(cj_method_t *method);

/**
 * 获取方法的access_flags.
 * @param method 方法
 * @return access flags
 */
u2 cj_method_get_access_flags(cj_method_t *method);

/**
 * 获取方法的属性数量.
 * @param method 方法
 * @return 属性数量
 */
u2 cj_method_get_attribute_count(cj_method_t *method);

/**
 * 根据索引值获取方法的属性.
 * 返回值不可被释放.
 * @param method 方法
 * @param idx 索引
 * @return 属性，如果不存在该索引值时，返回NULL.
 */
cj_attribute_t *cj_method_get_attribute(cj_method_t *method, u2 idx);

/**
 * 获取方法的注解数量.
 * @param method 方法
 * @return 注解数量
 */
u2 cj_method_get_annotation_count(cj_method_t *method);

/**
 * 根据索引值获取方法的注解.
 * 返回值不可被释放.
 * @param method 方法
 * @param idx 索引
 * @return 属性，如果不存在该索引值时，返回NULL.
 */
cj_annotation_t *cj_method_get_annotation(cj_method_t *method, u2 idx);

/**
 * 获取方法的代码.
 * 返回值不可被释放.
 * @param method 方法
 * @return 代码，如果不存在代码时，返回NULL
 */
cj_code_t *cj_method_get_code(cj_method_t *method);

/**
 * 获取方法参数数量.
 * @param method 方法
 * @return 方法数量
 */
u2 cj_method_get_parameter_count(cj_method_t *method);

/**
 * 获取方法返回值类型.
 * 返回值不可被释放.
 * @param method 方法
 * @return 返回值类型
 */
const_str cj_method_get_return_type(cj_method_t *method);

/**
 * 获取方法描述符.
 * 返回值不可被释放.
 * @param method 方法
 * @return 方法描述符
 */
cj_descriptor_t *cj_method_get_descriptor(cj_method_t *method);

/**
 * 方法生成字节码
 * 返回值需要释放.
 * @param method
 * @return
 */
cj_mem_buf_t *cj_method_to_buf(cj_method_t *method);

/**
 * 对方法进行重新命名
 * @param method
 * @return
 */
bool cj_method_rename(cj_method_t *method, unsigned char *name);

/**
 * 向当前方法中添加一个注解
 * @param method
 * @param annotation
 * @return
 */
bool cj_method_add_annotation(cj_method_t *method, cj_annotation_t *annotation);

cj_mem_buf_t *cj_method_group_to_buf(cj_class_t *cls, cj_method_group_t *group);

cj_method_group_t *cj_method_group_new(u2 count, u4 *heads, u4 *tails);

void cj_method_mark_dirty(cj_method_t *method, u4 flags);

CJ_INTERNAL cj_method_t *cj_method_group_get(cj_class_t *ctx, cj_method_group_t *set, u2 idx);

CJ_INTERNAL void cj_method_group_free(cj_method_group_t *set);

CJ_INTERNAL void cj_method_free(cj_method_t *method);

CJ_INTERNAL void cj_code_iterate(cj_code_t *code, void(*callback)(cj_insn_t *, void *ctx), void *ctx);

CJ_INTERNAL cj_code_iter_t cj_code_iter_start(cj_code_t *code);

CJ_INTERNAL bool cj_code_iter_has_next(cj_code_iter_t *iter);

CJ_INTERNAL cj_insn_t *cj_code_iter_next(cj_code_iter_t *iter);

CJ_INTERNAL void cj_insn_free(cj_insn_t *insn);

CJ_INTERNAL u2 cj_code_compute_max_stack(cj_code_t *code);

CJ_INTERNAL void cj_print_opcode(enum cj_opcode code);

#endif //CJASM_METHOD_H
