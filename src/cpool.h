//
// Created by Rieon Ke on 2020/7/21.
//

#ifndef CJASM_CPOOL_H
#define CJASM_CPOOL_H

#include "util.h"
#include "mem_buf.h"

/**
 * 跟据索引号从常量池中获取指定的字符串常量.
 * 返回值不可被释放.
 * @param ctx cj 类
 * @param idx 常量池索引，[1 - 常量池长度)
 * @return 字符串，当不存在该索引值或者该常量不是字符串类型时，返回NULL。
 */
const_str cj_cp_get_str(cj_class_t *ctx, u2 idx);

/**
 * 根据索引号从常量池中获取指定的4字节常量.
 * @param ctx 类
 * @param idx 常量池索引，[1 - 常量池长度)
 * @return 4字节常量
 */
u4 cj_cp_get_u4(cj_class_t *ctx, u2 idx);

/**
 * 根据索引号从常量池中获取指定的int常量
 * @param ctx
 * @param idx
 * @return
 */
int cj_cp_get_int(cj_class_t *ctx, u2 idx);

/**
 * 根据索引号从常量池中获取指定的char常量
 * @param ctx
 * @param idx
 * @return
 */
u2 cj_cp_get_char(cj_class_t *ctx, u2 idx);

/**
 * 根据索引号从常量池中获取指定的byte常量
 * @param ctx
 * @param idx
 * @return
 */

char cj_cp_get_byte(cj_class_t *ctx, u2 idx);

/**
 * 根据索引号从常量池中获取指定的boolean常量
 * @param ctx
 * @param idx
 * @return
 */
bool cj_cp_get_bool(cj_class_t *ctx, u2 idx);

/**
 * 根据索引号从常量池中获取指定的8字节常量
 * @param ctx 类
 * @param idx 常量池索引，[1 - 常量池长度)
 * @return 8字节常量
 */
u8 cj_cp_get_u8(cj_class_t *ctx, u2 idx);

/**
 * 根据索引号从常量池中获取指定的long常量
 * @param ctx
 * @param idx
 * @return
 */
long cj_cp_get_long(cj_class_t *ctx, u2 idx);

/**
 * 根据索引号从常量池中获取指定的float常量
 * @param ctx
 * @param idx
 * @return
 */
float cj_cp_get_float(cj_class_t *ctx, u2 idx);

/**
 * 根据索引号从常量池中获取指定的double常量
 * @param ctx
 * @param idx
 * @return
 */
double cj_cp_get_double(cj_class_t *ctx, u2 idx);

u2 cj_cp_put_u4(cj_class_t *ctx, u4 data);

u2 cj_cp_put_u8(cj_class_t *ctx, u8 data);

cj_cpool_t *cj_cp_parse(buf_ptr buf);

u4 cj_cp_get_tail_offset(cj_cpool_t *ctx);

cj_mem_buf_t *cj_cp_to_buf2(cj_class_t *ctx);

void cj_cp_free(cj_cpool_t *cpool);

CJ_INTERNAL bool cj_cp_update_str(cj_class_t *ctx, const_str name, size_t len, u2 index);

CJ_INTERNAL bool cj_cp_update_class(cj_class_t *ctx, u2 idx, u2 name_idx);

CJ_INTERNAL const_str cj_cp_put_str(cj_class_t *ctx, const_str name, size_t len, u2 *index);

CJ_INTERNAL void cj_cp_add_descriptor_idx(cj_cpool_t *cpool, u2 desc_idx);

CJ_INTERNAL u2 cj_cp_get_descriptor_idx(cj_cpool_t *cpool, u2 idx);

CJ_INTERNAL u2 cj_cp_get_descriptor_count(cj_cpool_t *cpool);

CJ_INTERNAL u2 cj_cp_get_class_idx(cj_cpool_t *cpool, u2 idx);

CJ_INTERNAL u2 cj_cp_get_class_count(cj_cpool_t *cpool);

CJ_INTERNAL u2 cj_cp_get_u2(cj_class_t *ctx, u2 idx);

CJ_INTERNAL u2 cj_cp_get_length(cj_cpool_t *cpool);

CJ_INTERNAL u2 cj_cp_get_str_index(cj_class_t *ctx, const_str str);

#endif //CJASM_CPOOL_H
