//
// Created by Rieon Ke on 2020/7/24.
//

#ifndef CJASM_ATTRIBUTE_H
#define CJASM_ATTRIBUTE_H

#include "util.h"


/**
 * 根据属性名解析属性类型.
 * @param type_str 属性名
 * @return 属性类型
 */
enum cj_attr_type cj_attr_parse_type(const_str type_str);

CJ_INTERNAL void cj_attribute_parse_offsets(buf_ptr ptr, u4 offset, u4 **offsets, u4 len);

CJ_INTERNAL cj_attribute_t *cj_attribute_group_get(cj_class_t *ctx, cj_attribute_group_t *set, u2 idx);

CJ_INTERNAL void cj_attribute_group_free(cj_attribute_group_t *set);

CJ_INTERNAL void cj_attribute_free(cj_attribute_t *attr);


#endif //CJASM_ATTRIBUTE_H
