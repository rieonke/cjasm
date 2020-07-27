//
// Created by Rieon Ke on 2020/7/23.
//

#ifndef CJASM_CLASS_H
#define CJASM_CLASS_H

#include <cjasm.h>
#include "annotation.h"
#include "mem_buf.h"

/**
 * 生成字节码.
 * @param ctx cj 类
 * @param out 输出字节码，使用后应被释放，出现错误时，输出为NULL
 * @param len 输出字节码长度，出现错误时，输出为0
 * @return 是否成功
 */
cj_mem_buf_t *cj_class_to_buf(cj_class_t *ctx);

bool cj_class_add_annotation(cj_class_t *ctx, cj_annotation_t *ann, bool visible);

cj_field_t *cj_class_get_field_by_name(cj_class_t *ctx, const_str name);

CJ_INTERNAL void cj_class_update_name(cj_class_t *ctx, const_str name);

bool cj_class_remove_field(cj_class_t *ctx, u2 idx);

bool cj_class_add_field(cj_class_t *ctx, cj_field_t *field);


#endif //CJASM_CLASS_H
