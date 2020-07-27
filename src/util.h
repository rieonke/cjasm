//
// Created by Rieon Ke on 2020/7/10.
//

#ifndef CJASM_UTIL_H
#define CJASM_UTIL_H

#include <cjasm.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>

#if defined(__APPLE__)

#include <machine/endian.h>
#include <libkern/OSByteOrder.h>

#if BYTE_ORDER == LITTLE_ENDIAN

#define btol16(x) OSSwapInt16(x)
#define btol32(x) OSSwapInt32(x)
#define btol64(x) OSSwapInt64(x)

#elif BYTE_ORDER == BIG_ENDIAN

#define btol16(x) (x)
#define btol32(x) (x)
#define btol64(x) (x)

#endif


#else

#error "unsupported os type"

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
#define CJ_INTERNAL
#define privc(c) ((cj_class_priv_t*)(c->priv))
#define privm(m) ((cj_method_priv_t*)(m->priv))
#define priva(a) ((cj_attribute_priv_t*)(a->priv))
#define privf(f) ((cj_field_priv_t*)(f->priv))
#define cj_sfree(ptr) if(ptr != NULL) free(ptr)

/**
 * 内部私有类型，用于存放过程变量，不可以被外部调用，不保证向后兼容性
 */
typedef struct cj_cp_entry_s cj_cp_entry_t;
typedef struct cj_class_priv_s cj_class_priv_t;
typedef struct cj_method_priv_s cj_method_priv_t;
typedef struct cj_field_priv_s cj_field_priv_t;
typedef struct cj_attribute_group_s cj_attribute_group_t;
typedef struct cj_method_group_s cj_method_group_t;
typedef struct cj_annotation_group_s cj_annotation_group_t;
typedef struct cj_annotation_priv_s cj_annotation_priv_t;
typedef struct cj_attribute_priv_s cj_attribute_priv_t;
typedef struct cj_code_iter_s cj_code_iter_t;
typedef struct cj_insn_s cj_insn_t;
typedef struct cj_cpool_s cj_cpool_t;
typedef struct cj_buf_s cj_buf_t;
typedef struct cj_field_group_s cj_field_group_t;

struct cj_buf_s {
    unsigned char *buf;
    unsigned int length;
};

struct cj_cp_entry_s {
    u1 tag;
    u2 len;
    unsigned char *data;
};

#define CJ_CACHEABLE_SET(name, type) \
struct name {                        \
    u2 index;                        \
    u2 count;                        \
    u4 *offsets;                     \
    type **cache;                    \
};

CJ_CACHEABLE_SET(cj_annotation_group_s, cj_annotation_t)
CJ_CACHEABLE_SET(cj_attribute_group_s, cj_attribute_t)
CJ_CACHEABLE_SET(cj_method_group_s, cj_method_t)


struct cj_field_group_s {
    u2 count;
    u4 *heads;
    u4 *tails;
    cj_field_t **fetched;
    struct hashmap_s *map;
};

struct cj_class_priv_s {
    //是否被改过标记
    unsigned int dirty;
    //类的字节码
    unsigned char const *buf;
    size_t buf_len;

    //此类的起始偏移量（常量池之后的起始位置）
    u4 header;
    cj_cpool_t *cpool;

    u2 this_class;
    u2 super_class;

    cj_field_group_t *field_group;
    cj_attribute_group_t **field_attribute_groups;

    cj_method_group_t *method_group;
    cj_attribute_group_t **method_attribute_groups;

    cj_attribute_group_t *attribute_group;
    bool annotation_set_initialized;
    cj_annotation_group_t *annotation_group;

    bool initialized;
};

struct cj_method_priv_s {
    u4 offset;
    bool annotation_set_initialized;
    cj_annotation_group_t *annotation_group;
    cj_attribute_group_t *attribute_group;
    cj_code_t *code;
    cj_descriptor_t *descriptor;
};

struct cj_field_priv_s {
    unsigned int dirty;
    u4 head;
    u4 tail;
    bool annotation_set_initialized;
    cj_annotation_group_t *annotation_group;
    cj_attribute_group_t *attribute_group;
};

struct cj_attribute_priv_s {
    u4 offset;
};

struct cj_annotation_priv_s {
    u4 offset;
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

#define cj_strcmp(str1, str2) (strcmp((char*)(str1), (char*)(str2)) == 0)

#define cj_n2pow(v) \
    v--;            \
    for (size_t _cj_n2pow_i_ = 1; _cj_n2pow_i_ < sizeof(v) * CHAR_BIT; _cj_n2pow_i_ *= 2) { \
        v |= v >> _cj_n2pow_i_;       \
    }                  \
    ++v


#endif //CJASM_UTIL_H
