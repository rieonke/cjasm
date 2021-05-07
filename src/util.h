//
// Created by Rieon Ke on 2020/7/10.
//

#ifndef CJASM_UTIL_H
#define CJASM_UTIL_H

#include "def.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include "endianness.h"

#define btol16(x) end_be16toh(x)
#define btol32(x) end_be32toh(x)
#define btol64(x) end_be64toh(x)

#if HAVE_FUNC_STRNDUP == 0

inline char *strndup(const char *str, unsigned int len) {
    char *out = malloc(len + 1);
    memset(out + len, 0, 1);
    memcpy(out, str, len);
    return out;
}

#endif


//todo impl windows & linux
/**
 * 从字节码里读取N个字节，并且将大端转化为本地的大小端表示
 */
#define cj_ri1(ptr) (*(i1 *) (ptr))
#define cj_ri2(ptr) btol16(*(i2 *) (ptr)) /*NOLINT*/
#define cj_ri4(ptr) btol32(*(i4 *) (ptr)) /*NOLINT*/
#define cj_ri8(ptr) btol64(*(i8 *) (ptr)) /*NOLINT*/

#define cj_ru1(ptr) (*(u1 *) (ptr))
#define cj_ru2(ptr) btol16(*(u2 *) (ptr)) /*NOLINT*/
#define cj_ru4(ptr) btol32(*(u4 *) (ptr)) /*NOLINT*/
#define cj_ru8(ptr) btol64(*(u8 *) (ptr)) /*NOLINT*/

#define cj_wu1(ptr, data) *(u1*)(ptr) = data
#define cj_wu2(ptr, data) *(u2*)(ptr) = btol16(data) /*NOLINT*/
#define cj_wu4(ptr, data) *(u4*)(ptr) = btol32(data) /*NOLINT*/
#define cj_wu8(ptr, data) *(u8*)(ptr) = btol64(data) /*NOLINT*/

#define cj_wi1(ptr, data) *(i1*)(ptr) = data
#define cj_wi2(ptr, data) *(i2*)(ptr) = btol16(data) /*NOLINT*/
#define cj_wi4(ptr, data) *(i4*)(ptr) = btol32(data) /*NOLINT*/
#define cj_wi8(ptr, data) *(i8*)(ptr) = btol64(data) /*NOLINT*/

/**
 * 用来表示内部使用的函数，不是公开的方法，不建议被外部调用，不保证向后兼容性
 */
#define cj_sfree(ptr) if(ptr != NULL) free(ptr)

/**
 * 内部私有类型，用于存放过程变量，不可以被外部调用，不保证向后兼容性
 */
struct cj_buf_s {
    unsigned char *buf;
    unsigned int length;
};

struct cj_code_iter_s {
    cj_code_t *code;
    u4 current;
    u4 length;
};

enum insn_type {
    NONE,
    INSN,
    VAR,
    JUMP,
    IINC,
    TABLE_SWITCH,
    LOOKUP_SWITCH,
    INT,
    LDC,
    FIELD,
    METHOD,
    INVOKE_DYNAMIC,
    TYPE,
    MULTI_ANEWARRAY
};

struct cj_insn_s {
    enum cj_opcode opcode;
    enum insn_type type;
    u4 mark;
    int var;
    int val;
    int label;
    int index;

    u2 cp_idx;

    int incr;
    int s_low;
    int s_high;
    int s_default;
    int *s_labels;
    int s_pairs;
    int *s_keys;

    u1 dimensions;

};

//@formatter:off
/**
 * 常量池的类型
 */
enum cj_cp_type {
    CONSTANT_Class              =   7 ,
    CONSTANT_Fieldref           =   9 ,
    CONSTANT_Methodref          =  10 ,
    CONSTANT_InterfaceMethodref =  11 ,
    CONSTANT_String             =   8 ,
    CONSTANT_Integer            =   3 ,
    CONSTANT_Float              =   4 ,
    CONSTANT_Long               =   5 ,
    CONSTANT_Double             =   6 ,
    CONSTANT_NameAndType        =  12 ,
    CONSTANT_Utf8               =   1 ,
    CONSTANT_MethodHandle       =  15 ,
    CONSTANT_MethodType         =  16 ,
    CONSTANT_Dynamic            =  17 ,
    CONSTANT_InvokeDynamic      =  18 ,
    CONSTANT_Module             =  19 ,
    CONSTANT_Package            =  20 ,
};
//@formatter:on

#define cj_streq(str1, str2) (strcmp((char*)(str1), (char*)(str2)) == 0)

#define cj_str_replace(str, len, find, replace) \
    {                                           \
        for (int i = 0; i < len; ++i ) {        \
            if (str[i] == (char)find) {         \
                ((char*)str)[i] = replace;      \
            }                                   \
        }                                       \
    }

#define cj_n2pow(v)                                                                         \
    v--;                                                                                    \
    for (size_t _cj_n2pow_i_ = 1; _cj_n2pow_i_ < sizeof(v) * CHAR_BIT; _cj_n2pow_i_ *= 2) { \
        v |= v >> _cj_n2pow_i_;                                                             \
    }                                                                                       \
    ++v

/*todo 如果所加入的attr已经存在了，则获取现有的，impl cj_attribute_group_add_or_get */ \

#define cj_annotation_group_init_or_create(comp, visible)                                                           \
    if (!priv(comp)->annotation_set_initialized) {                                                                  \
        priv(comp)->annotation_set_initialized = cj_annotation_group_init(comp->klass, priv(comp)->attribute_group, \
                                                                      &priv(comp)->annotation_group);               \
    }                                                                                                               \
    if (priv(comp)->attribute_group == NULL) {                                                                      \
        cj_attribute_group_t *group = cj_attribute_group_new(0, NULL, NULL);                                        \
        priv(comp)->attribute_group = group;                                                                        \
    }                                                                                                               \
    if (priv(comp)->annotation_group == NULL) {                                                                     \
        cj_annotation_group_t *ann_group = cj_annotation_group_create(0);                                           \
        priv(comp)->annotation_group = ann_group;                                                                   \
    }                                                                                                               \
    if (visible && priv(comp)->annotation_group->vi_attr == NULL  ) {                                               \
        cj_attribute_t *attribute = cj_attribute_new(CJ_ATTR_RuntimeVisibleAnnotations);                            \
        priv(comp)->annotation_group->vi_attr = attribute;                                                          \
        cj_attribute_group_add(comp->klass, priv(comp)->attribute_group, attribute);                                \
        cj_attribute_set_data(attribute, priv(comp)->annotation_group);                                             \
    }                                                                                                               \
    if (!visible &&  priv(comp)->annotation_group->in_attr == NULL) {                                               \
        cj_attribute_t *attribute = cj_attribute_new(CJ_ATTR_RuntimeInvisibleAnnotations);                          \
        priv(comp)->annotation_group->in_attr = attribute;                                                          \
        cj_attribute_group_add(comp->klass, priv(comp)->attribute_group, attribute);                                \
        cj_attribute_set_data(attribute, priv(comp)->annotation_group);                                             \
    }


/**
 * read file content into char buffer.
 * @param path file path
 * @param buf out buffer
 * @return buffer size, error occurred if less than 0
 */
long cj_load_file(char *path, unsigned char **buf);

#endif //CJASM_UTIL_H
