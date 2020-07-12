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

#define cj_ri1(ptr) (*(i1 *) (ptr))
#define cj_ri2(ptr) btol16(*(i2 *) (ptr)) /*NOLINT*/
#define cj_ri4(ptr) btol32(*(i4 *) (ptr)) /*NOLINT*/
#define cj_ru1(ptr) (*(u1 *) (ptr))
#define cj_ru2(ptr) btol16(*(u2 *) (ptr)) /*NOLINT*/
#define cj_ru4(ptr) btol32(*(u4 *) (ptr)) /*NOLINT*/
#define cj_ru8(ptr) btol64(*(u8 *) (ptr)) /*NOLINT*/

#define CJ_INTERNAL
#define priv(c) ((cj_class_priv_t*)(c->priv))
#define cj_sfree(ptr) if(ptr != NULL) free(ptr);

typedef struct cj_cp_entry_s cj_cp_entry_t;
struct cj_cp_entry_s {
    u1 tag;
    u2 len;
    unsigned char *data;
};


typedef struct cj_class_priv_s cj_class_priv_t;
struct cj_class_priv_s {
    bool dirty;
    unsigned char const *buf;
    size_t buf_len;

    u4 header;

    u2 cp_len;
    u1 *cp_types;
    u2 *cp_offsets;
    unsigned char **cp_cache;
    cj_cp_entry_t **cp_entries;
    u2 cp_entries_len;

    u2 this_class;
    u2 super_class;

    cj_field_t **field_cache;
    u2 *field_offsets;

    u2 *method_offsets;
    u4 attribute_offset;
};

//@formatter:off
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

static void print_type(enum cj_cp_type t) {

#define PRINT_TYPE(t) \
    case t: \
        printf("%s", #t);\
        break;

    switch (t) {
        PRINT_TYPE(CONSTANT_Class)
        PRINT_TYPE(CONSTANT_Fieldref)
        PRINT_TYPE(CONSTANT_Methodref)
        PRINT_TYPE(CONSTANT_InterfaceMethodref)
        PRINT_TYPE(CONSTANT_String)
        PRINT_TYPE(CONSTANT_Integer)
        PRINT_TYPE(CONSTANT_Float)
        PRINT_TYPE(CONSTANT_Long)
        PRINT_TYPE(CONSTANT_Double)
        PRINT_TYPE(CONSTANT_NameAndType)
        PRINT_TYPE(CONSTANT_Utf8)
        PRINT_TYPE(CONSTANT_MethodHandle)
        PRINT_TYPE(CONSTANT_MethodType)
        PRINT_TYPE(CONSTANT_Dynamic)
        PRINT_TYPE(CONSTANT_InvokeDynamic)
        PRINT_TYPE(CONSTANT_Module)
        PRINT_TYPE(CONSTANT_Package)
    }

#undef PRINT_TYPE
}

static const unsigned char *cj_cp_put_str(cj_class_t *ctx, const unsigned char *name, size_t len, u2 *index) {
    // 检查现有的常量池中是否有当前字符串
    // 如果有，则直接返回现有的字符串
    // 如果不存在，则将该字符串放置于新的常量池中
    for (int i = 1; i < priv(ctx)->cp_len; ++i) {
        u1 type = priv(ctx)->cp_types[i];
        if (type == CONSTANT_Utf8) {
            const unsigned char *str = cj_cp_get_str(ctx, i);
            if (strncmp((char *) str, (char *) name, len) == 0) {
                if (index != NULL) *index = i;
                return str;
            }
        } else if (type == CONSTANT_Long || type == CONSTANT_Double) {
            i++;
        }
    }

    u2 cur_idx = priv(ctx)->cp_entries_len++;
    if (priv(ctx)->cp_entries == NULL) {
        priv(ctx)->cp_entries = malloc(sizeof(cj_cp_entry_t *));
    } else {
        priv(ctx)->cp_entries = realloc(priv(ctx)->cp_entries, sizeof(cj_cp_entry_t *) * priv(ctx)->cp_entries_len);
    }

    cj_cp_entry_t *entry = malloc(sizeof(cj_cp_entry_t));
    entry->tag = CONSTANT_Utf8;
    entry->len = len;
    entry->data = (unsigned char *) strndup((char *) name, len);

    if (index != NULL) {
        *index = cur_idx + priv(ctx)->cp_len - 1;
    }

    priv(ctx)->cp_entries[cur_idx] = entry;
    return entry->data;
}

#endif //CJASM_UTIL_H
