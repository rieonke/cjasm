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
#define cj_ru1(ptr) (*(u1 *) (ptr))
#define cj_ru2(ptr) btol16(*(u2 *) (ptr)) /*NOLINT*/
#define cj_ru4(ptr) btol32(*(u4 *) (ptr)) /*NOLINT*/
#define cj_ru8(ptr) btol64(*(u8 *) (ptr)) /*NOLINT*/

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
typedef struct cj_attribute_set_s cj_attribute_set_t;
typedef struct cj_method_set_s cj_method_set_t;
typedef struct cj_field_set_s cj_field_set_t;
typedef struct cj_annotation_set_s cj_annotation_set_t;
typedef struct cj_annotation_priv_s cj_annotation_priv_t;
typedef struct cj_attribute_priv_s cj_attribute_priv_t;
typedef struct cj_code_iter_s cj_code_iter_t;
typedef struct cj_insn_s cj_insn_t;

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

CJ_CACHEABLE_SET(cj_annotation_set_s, cj_annotation_t)
CJ_CACHEABLE_SET(cj_attribute_set_s, cj_attribute_t)
CJ_CACHEABLE_SET(cj_method_set_s, cj_method_t)
CJ_CACHEABLE_SET(cj_field_set_s, cj_field_t)

struct cj_class_priv_s {
    //是否被改过标记
    bool dirty;
    //类的字节码
    unsigned char const *buf;
    size_t buf_len;

    //此类的起始偏移量（常量池之后的起始位置）
    u4 header;

    //常量池大小
    u2 cp_len;
    //常量类型数组
    u1 *cp_types;
    //常量池偏移量数组
    u2 *cp_offsets;
    //
    unsigned char **cp_cache;
    //
    cj_cp_entry_t **cp_entries;

    u2 cp_entries_len;

    u2 this_class;
    u2 super_class;

    cj_field_set_t *field_set;
    cj_attribute_set_t **field_attribute_sets;

    cj_method_set_t *method_set;
    cj_attribute_set_t **method_attribute_sets;

    cj_attribute_set_t *attribute_set;
    bool annotation_set_initialized;
    cj_annotation_set_t *annotation_set;
};

struct cj_method_priv_s {
    u4 offset;
    bool annotation_set_initialized;
    cj_annotation_set_t *annotation_set;
    cj_attribute_set_t *attribute_set;
    cj_code_t *code;
    cj_descriptor_t *descriptor;
};

struct cj_field_priv_s {
    u4 offset;
    bool annotation_set_initialized;
    cj_annotation_set_t *annotation_set;
    cj_attribute_set_t *attribute_set;
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

CJ_INTERNAL cj_annotation_t *cj_annotation_parse(cj_class_t *ctx, buf_ptr attr_ptr, u4 *out_offset);

CJ_INTERNAL cj_element_t *cj_annotation_parse_element_value(cj_class_t *ctx, buf_ptr ev_ptr, u4 *out_offset);

CJ_INTERNAL const_str cj_cp_put_str(cj_class_t *ctx, const_str name, size_t len, u2 *index);

CJ_INTERNAL void cj_attribute_parse_offsets(buf_ptr ptr, u4 offset, u4 **offsets, u4 len);

CJ_INTERNAL cj_attribute_t *cj_attribute_set_get(cj_class_t *ctx, cj_attribute_set_t *set, u2 idx);

CJ_INTERNAL void cj_attribute_set_free(cj_attribute_set_t *set);

CJ_INTERNAL cj_method_t *cj_method_set_get(cj_class_t *ctx, cj_method_set_t *set, u2 idx);

CJ_INTERNAL void cj_method_set_free(cj_method_set_t *set);

CJ_INTERNAL cj_field_t *cj_field_set_get(cj_class_t *ctx, cj_field_set_t *set, u2 idx);

CJ_INTERNAL void cj_field_set_free(cj_field_set_t *set);

CJ_INTERNAL void cj_field_free(cj_field_t *field);

CJ_INTERNAL void cj_attribute_free(cj_attribute_t *attr);

CJ_INTERNAL void cj_method_free(cj_method_t *method);

CJ_INTERNAL void cj_annotation_free(cj_annotation_t *ann);

CJ_INTERNAL bool cj_annotation_set_init(cj_class_t *ctx, cj_attribute_set_t *attr_set, cj_annotation_set_t **set);

CJ_INTERNAL cj_annotation_t *cj_annotation_set_get(cj_class_t *ctx, cj_annotation_set_t *set, u2 idx);

CJ_INTERNAL void cj_annotation_set_free(cj_annotation_set_t *set);

CJ_INTERNAL cj_descriptor_t *cj_descriptor_parse(const_str desc, size_t len);

CJ_INTERNAL void cj_descriptor_free(cj_descriptor_t *desc);

CJ_INTERNAL void cj_code_iterate(cj_code_t *code, void(*callback)(cj_insn_t *, void *ctx), void *ctx);

CJ_INTERNAL cj_code_iter_t cj_code_iter_start(cj_code_t *code);

CJ_INTERNAL bool cj_code_iter_has_next(cj_code_iter_t *iter);

CJ_INTERNAL cj_insn_t *cj_code_iter_next(cj_code_iter_t *iter);

CJ_INTERNAL void cj_insn_free(cj_insn_t *insn);

CJ_INTERNAL u2 cj_code_compute_max_stack(cj_code_t *code);

CJ_INTERNAL void cj_print_opcode(enum cj_opcode code);

#endif //CJASM_UTIL_H
