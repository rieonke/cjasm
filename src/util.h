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
#define privc(c) ((cj_class_priv_t*)(c->priv))
#define privm(m) ((cj_method_priv_t*)(m->priv))
#define cj_sfree(ptr) if(ptr != NULL) free(ptr)

typedef struct cj_cp_entry_s cj_cp_entry_t;
struct cj_cp_entry_s {
    u1 tag;
    u2 len;
    unsigned char *data;
};


typedef struct cj_class_priv_s cj_class_priv_t;
typedef struct cj_method_priv_s cj_method_priv_t;
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
    u4 *field_offsets;

    cj_method_t **method_cache;
    u4 *method_offsets;

    cj_attribute_t **attr_cache;
    u4 *attr_offsets;

    u2 ann_count;
    bool ann_initialized;
    bool ann_parsed;
    cj_annotation_t **ann_cache;
};

struct cj_method_priv_s {
    u4 offset;
    u4 *attribute_offsets;
    cj_attribute_t **attribute_cache;
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
        default:
            printf("UNKNOWN TYPE");
    }

#undef PRINT_TYPE
}

CJ_INTERNAL static cj_annotation_t *
cj_annotation_parse(cj_class_t *ctx, const unsigned char *attr_ptr, u4 *out_offset);

CJ_INTERNAL static cj_element_t *
cj_annotation_parse_element_value(cj_class_t *ctx, const unsigned char *ev_ptr, u4 *out_offset);

CJ_INTERNAL static const_str cj_cp_put_str(cj_class_t *ctx, const_str name, size_t len, u2 *index);

CJ_INTERNAL static void cj_attribute_parse_offsets(buf_ptr ptr, u4 offset, u4 **offsets, u4 len);

CJ_INTERNAL static const_str cj_cp_put_str(cj_class_t *ctx, const_str name, size_t len, u2 *index) {
    // 检查现有的常量池中是否有当前字符串
    // 如果有，则直接返回现有的字符串
    // 如果不存在，则将该字符串放置于新的常量池中
    for (int i = 1; i < privc(ctx)->cp_len; ++i) {
        u1 type = privc(ctx)->cp_types[i];
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

    u2 cur_idx = privc(ctx)->cp_entries_len++;
    if (privc(ctx)->cp_entries == NULL) {
        privc(ctx)->cp_entries = malloc(sizeof(cj_cp_entry_t *));
    } else {
        privc(ctx)->cp_entries = realloc(privc(ctx)->cp_entries, sizeof(cj_cp_entry_t *) * privc(ctx)->cp_entries_len);
    }

    cj_cp_entry_t *entry = malloc(sizeof(cj_cp_entry_t));
    entry->tag = CONSTANT_Utf8;
    entry->len = len;
    entry->data = (unsigned char *) strndup((char *) name, len);

    if (index != NULL) {
        *index = cur_idx + privc(ctx)->cp_len - 1;
    }

    privc(ctx)->cp_entries[cur_idx] = entry;
    return entry->data;
}


CJ_INTERNAL static cj_annotation_t *cj_annotation_parse(cj_class_t *ctx, buf_ptr attr_ptr, u4 *out_offset) {

    u4 offset = out_offset == NULL ? 0 : *out_offset;
    cj_annotation_t *annotation = NULL;
    cj_element_pair_t **pairs = NULL;

    /*
     * annotation {
     *     u2 type_index;
     *     u2 num_element_value_pairs;
     *     {   u2            element_name_index;
     *         element_value value;
     *     } element_value_pairs[num_element_value_pairs];
     * }
     *
     */
    u2 type_index = cj_ru2(attr_ptr + offset);
    u2 num_pairs = cj_ru2(attr_ptr + offset + 2);

    offset += 4;

    if (num_pairs > 0) {
        pairs = malloc(sizeof(cj_element_pair_t *) * num_pairs);
        for (int j = 0; j < num_pairs; ++j) {

            cj_element_pair_t *pair = malloc(sizeof(cj_element_pair_t));

            u2 element_name_index = cj_ru2(attr_ptr + offset);
            offset += 2;
            cj_element_t *element = cj_annotation_parse_element_value(ctx, attr_ptr, &offset);
            pair->name = cj_cp_get_str(ctx, element_name_index);
            pair->value = element;

            pairs[j] = pair;
        }
    }

    annotation = malloc(sizeof(cj_annotation_t));
    annotation->type_name = cj_cp_get_str(ctx, type_index);
    annotation->attributes_count = num_pairs;
    annotation->attributes = pairs;

    if (out_offset != NULL) *out_offset = offset;
    return annotation;
}

CJ_INTERNAL static cj_element_t *
cj_annotation_parse_element_value(cj_class_t *ctx, const unsigned char *ev_ptr, u4 *out_offset) {

    u4 offset = out_offset == NULL ? 0 : *out_offset;
    cj_element_t *ev = calloc(sizeof(cj_element_t), 1);

    /*
     * element_value {
     *     u1 tag;
     *     union {
     *         u2 const_value_index;
     *         {   u2 type_name_index;
     *             u2 const_name_index;
     *         } enum_const_value;
     *         u2 class_info_index;
     *         annotation annotation_value;
     *         {   u2            num_values;
     *             element_value values[num_values];
     *         } array_value;
     *     } value;
     * }
     *
     *
     *  +-----+------------+-------------------------------------+
     *  | tag |    Type    |    value Item     |  Constant Type   |
     *  +-----+------------+-------------------+------------------+
     *  | B   | byte       | const_value_index | CONSTANT_Integer |
     *  | C   | char       | const_value_index | CONSTANT_Integer |
     *  | D   | double     | const_value_index | CONSTANT_Double  |
     *  | F   | float      | const_value_index | CONSTANT_Float   |
     *  | I   | int        | const_value_index | CONSTANT_Integer |
     *  | J   | long       | const_value_index | CONSTANT_Long    |
     *  | S   | short      | const_value_index | CONSTANT_Integer |
     *  | Z   | boolean    | const_value_index | CONSTANT_Integer |
     *  | s   | String     | const_value_index | CONSTANT_Utf8    |
     *  | e   | Enum       | enum_const_value  | Not applicable   |
     *  | c   | Class      | class_info_index  | Not applicable   |
     *  | @   | Annotation | annotation_value  | Not applicable   |
     *  | [   | Array      | array_value       | Not applicable   |
     *  +-----+------------+-------------------+------------------+
     */

    u1 tag = cj_ru1(ev_ptr + offset++);
    ev->tag = tag;
    switch (tag) {
        case 'B': /*byte*/
        case 'C': /*char*/
        case 'I': /*int*/
        case 'S': /*short*/
        case 'Z': /*boolean*/
        case 'F': /*float*/
        {
            u2 idx = cj_ru2(ev_ptr + offset);
            u4 val = cj_cp_get_u4(ctx, idx);
            ev->const_num = val;
            break;
        }
        case 'D': /*double*/
        case 'J': /*long*/
        {
            u2 idx = cj_ru2(ev_ptr + offset);
            u8 val = cj_cp_get_u8(ctx, idx);
            ev->const_num = val;
            break;
        }
        case 's':/*string*/
        {
            u2 idx = cj_ru2(ev_ptr + offset);
            ev->const_str = cj_cp_get_str(ctx, idx);
            offset += 2;
            break;
        }
        case 'e': /*enum*/
        {
            u2 type_name_idx = cj_ru2(ev_ptr + offset);
            u2 const_name_idx = cj_ru2(ev_ptr + offset + 2);
            offset += 4;

            ev->type_name = cj_cp_get_str(ctx, type_name_idx);
            ev->const_name = cj_cp_get_str(ctx, const_name_idx);
            break;
        }
        case 'c': /*class*/
        {
            u2 class_idx = cj_ru2(ev_ptr + offset);
            offset += 2;
            ev->class_info_index = class_idx;
            break;
        }
        case '@': /*annotation*/
        {
            ev->annotation = cj_annotation_parse(ctx, ev_ptr, &offset); //fixme check error
            break;
        }
        case '[': /*array*/
        {
            u2 ev_count = cj_ru2(ev_ptr + offset);
            offset += 2;
            cj_element_t **element_values = NULL;

            if (ev_count > 0) {
                element_values = malloc(sizeof(cj_element_t) * ev_count);
                for (int i = 0; i < ev_count; ++i) {
                    element_values[i] = cj_annotation_parse_element_value(ctx, ev_ptr, &offset); //fixme check error
                }
            }
            ev->element_count = ev_count;
            ev->elements = element_values;
        }
        default:
            cj_sfree(ev);
            fprintf(stderr, "ERROR: invalid annotation, unknown element value tag: %c\n", tag);
            return NULL;
    }


    if (out_offset != NULL)
        *out_offset = offset;

    return ev;
}

CJ_INTERNAL static void cj_attribute_parse_offsets(buf_ptr ptr, u4 offset, u4 **offsets, u4 len) {
    if (len == 0) {
        return;
    }

    if (*offsets == NULL) {
        *offsets = malloc(sizeof(u4) * len);
    }

    for (int i = 0; i < len; ++i) {
        *offsets[i] = offset;
        /*
         * attribute_info {
         *    u2 attribute_name_index;
         *    u4 attribute_length;
         *    u1 info[attribute_length];
         * }
         * 
         */
        u4 attribute_length = cj_ru4(ptr + offset + 2);
        offset += 6 + attribute_length;
    }

}

#endif //CJASM_UTIL_H
