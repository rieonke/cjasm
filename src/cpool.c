//
// Created by Rieon Ke on 2020/7/21.
//

#include <math.h>
#include "cpool.h"
#include "hashmap.h"
#include "class.h"
#include "mem_buf.h"


struct cj_cpool_s {
    //常量类型数组
    u1 *types;
    //常量池偏移量数组
    u4 *offsets;
    //常量池大小
    u2 length;
    unsigned char **cache;
    u4 tail_offset;

    cj_cp_entry_t **entries;
    u2 entries_len;
    u2 *touched;

    u2 *descriptors;
    u2 descriptors_len;

    u2 *classes;
    u2 classes_len;

    struct hashmap_s *map;
};

cj_mem_buf_t *cj_cp_to_buf2(cj_class_t *ctx) {

    cj_mem_buf_t *buf = cj_mem_buf_new();

    buf_ptr ptr = privc(ctx)->buf;
    cj_cpool_t *cpool = privc(ctx)->cpool;
    u2 cpool_len = cpool->length; //常量池从1开始

    u4 start = 10;
    u4 stop = 0;

    u2 *copied_indexes = calloc(cpool->entries_len, sizeof(u2));

    cj_mem_buf_write_u2(buf, 0);

#undef move
#define move() \
      if (out_buf == NULL) { \
         out_buf = malloc(sizeof(char) * out_buf_len);\
      }else {  \
         out_buf = realloc(out_buf, sizeof(char ) * (out_buf_len + buffer_pos)); \
      }\
      memcpy(out_buf + out_buf_len, buffer, buffer_pos);      \
      out_buf_len += buffer_pos;                   \
      buffer_pos = 0;

    //find untouched
    for (int i = 1; i < cpool->length; ++i) {

        u2 new_idx = cpool->touched[i];
        if (new_idx == 0) {
            //find next entry index
            if (i != cpool_len - 1) {
                stop = cpool->offsets[i + 1] - 1;
                continue;
            } else {
                stop = cpool->tail_offset;
            }
        }

        //1. 拷贝上一分支累积的数据
        u4 to_cpoy = stop - start;
        if (to_cpoy > 0) {
            cj_mem_buf_write_str(buf, (char *) ptr + start, to_cpoy);
            // memcpy(buffer + buffer_pos, ptr + start, to_cpoy);
            // buffer_pos += to_cpoy;
        }

        if (new_idx == 0) continue;
        start = cpool->offsets[i + 1] - 1;


        u1 tag = 0;
        u2 len = 0;
        unsigned char *data = NULL;
        if (new_idx < cpool->length) { //如果当前的索引在旧有的常量池中，则直接拷贝原有的
            //todo 假设只有utf类型
            tag = CONSTANT_Utf8;
            u4 offsets = cpool->offsets[new_idx];
            len = cj_ru2(ptr + offsets);
            data = (unsigned char *) ptr + offsets + 2;
        } else {
            new_idx = new_idx - cpool->length;
            cj_cp_entry_t *entry = cpool->entries[new_idx];
            tag = entry->tag;
            len = entry->len;
            data = entry->data;
            copied_indexes[new_idx] = 1;
        }


        //2. 拷贝entries中的数据
        cj_mem_buf_write_u1(buf, tag);

        if (tag == CONSTANT_Utf8) {
            cj_mem_buf_write_u2(buf, len);
            cj_mem_buf_write_str(buf, (char *) data, len);
        }

    }

    //generate new buf
    for (int i = 0; i < cpool->entries_len; ++i) {
//        if (copied_indexes[i] == 1) continue;
        //fixme 检查buffer是否已满
        cj_cp_entry_t *entry = cpool->entries[i];

        cj_mem_buf_write_u1(buf, entry->tag);

        if (entry->tag == CONSTANT_Utf8) {
            cj_mem_buf_write_u2(buf, entry->len);
            cj_mem_buf_write_str(buf, (char *) entry->data, entry->len);
        }

        cpool_len++;
    }

    free(copied_indexes);
    cj_mem_buf_flush(buf);

    cj_wu2(buf->data, cpool_len);

    return buf;
}

cj_cpool_t *cj_cp_parse(buf_ptr buf) {

    //常量池的个数
    u2 cp_len = cj_ru2(buf + 8);

    //todo check version

    //分配内存
    u4 *cp_offsets = malloc(cp_len * sizeof(u4)); //常量池偏移地址映射，根据常量下标[1,cp_len)获取，第0位元素弃用
    u1 *cp_types = malloc(cp_len * sizeof(u1));
    u2 *descriptors = malloc(cp_len * sizeof(u2));
    u2 descriptors_len = 0;
    u2 *classes = malloc(cp_len * sizeof(u2));
    u2 classes_len = 0;

    unsigned char **fetched = calloc(cp_len, sizeof(unsigned char *));
    struct hashmap_s *map = malloc(sizeof(struct hashmap_s));

    u2 map_len = cp_len;
    cj_n2pow(map_len);

    hashmap_create(map_len, map);

    int cur_cp_idx = 1;
    u4 cur_cp_offset = 10;
    while (cur_cp_idx < cp_len) {

        int cp_size;
        enum cj_cp_type type = (enum cj_cp_type) cj_ru1(buf + cur_cp_offset++);

        *(cp_types + cur_cp_idx) = type;
        *(cp_offsets + cur_cp_idx) = cur_cp_offset;
        //判断常量池中每个常量的类型
        switch (type) {
            /*+-----------------------------+-----+--------+
              |        Constant Kind        | Tag | Length |
              +-----------------------------+-----+--------+
              | CONSTANT_Class              |   7 | 2      |
              | CONSTANT_Fieldref           |   9 | 4      |
              | CONSTANT_Methodref          |  10 | 4      |
              | CONSTANT_InterfaceMethodref |  11 | 4      |
              | CONSTANT_String             |   8 | 2      |
              | CONSTANT_Integer            |   3 | 4      |
              | CONSTANT_Float              |   4 | 4      |
              | CONSTANT_Long               |   5 | 8      |
              | CONSTANT_Double             |   6 | 8      |
              | CONSTANT_NameAndType        |  12 | 4      |
              | CONSTANT_Utf8               |   1 | 2+     |
              | CONSTANT_MethodHandle       |  15 | 3      |
              | CONSTANT_MethodType         |  16 | 2      |
              | CONSTANT_Dynamic            |  17 | 4      |
              | CONSTANT_InvokeDynamic      |  18 | 4      |
              | CONSTANT_Module             |  19 | 2      |
              | CONSTANT_Package            |  20 | 2      |
              +-----------------------------+-----+--------+ */
            case CONSTANT_Class: {
                //2
                u2 name_index = cj_ru2(buf + cur_cp_offset);
                classes[classes_len++] = name_index;
                cp_size = 2;
                break;
            }
            case CONSTANT_String:
                //2
                cp_size = 2;
                break;
            case CONSTANT_Fieldref:
            case CONSTANT_Methodref:
            case CONSTANT_InterfaceMethodref:
                cp_size = 4;
                //4
                break;
            case CONSTANT_Float:
            case CONSTANT_Integer:
                cp_size = 4;
                //4
                break;
            case CONSTANT_Long:
            case CONSTANT_Double:
                cp_size = 8;
                cur_cp_idx++;
                //8
                break;
            case CONSTANT_NameAndType: {
                u2 descriptor_idx = cj_ru2(buf + cur_cp_offset + 2);
                descriptors[descriptors_len++] = descriptor_idx;
                cp_size = 4;
                //4
                break;
            }
            case CONSTANT_MethodHandle:
                cp_size = 3;
                //3
                break;
            case CONSTANT_MethodType: {
                u2 descriptor_idx = cj_ru2(buf + cur_cp_offset);
                descriptors[descriptors_len++] = descriptor_idx;
                cp_size = 2;
                //2
                break;
            }
            case CONSTANT_Dynamic:
            case CONSTANT_InvokeDynamic:
                cp_size = 4;
                //4
                break;
            case CONSTANT_Module:
            case CONSTANT_Package:
                cp_size = 2;
                //2
                break;
            case CONSTANT_Utf8: {
                u2 len = cj_ru2(buf + cur_cp_offset);
                cp_size = 2 + len;

                unsigned char *str = malloc(sizeof(char) * (len + 1));
                str[len] = 0;
                memcpy(str, buf + cur_cp_offset + 2, len);
                fetched[cur_cp_idx] = str;

                hashmap_put(map, (char *) str, len, (void *) (0L + cur_cp_idx));
                break;
            }
            default:
                fprintf(stderr, "ERROR: invalid class format, unrecognized cp entry tag: %d\n", type);
                free(cp_offsets);
                return NULL;
        }
        //设置当前常量的截止位置
        cur_cp_offset += cp_size;
        cur_cp_idx++;
    }


    cj_cpool_t *cpool = malloc(sizeof(cj_cpool_t));
    cpool->length = cp_len;
    cpool->types = cp_types;
    cpool->cache = fetched;
    cpool->touched = calloc(cp_len, sizeof(u2));
    cpool->offsets = cp_offsets;
    cpool->entries = NULL;
    cpool->entries_len = 0;
    cpool->tail_offset = cur_cp_offset;
    cpool->descriptors = descriptors;
    cpool->descriptors_len = descriptors_len;
    cpool->classes = classes;
    cpool->classes_len = classes_len;
    cpool->map = map;
    return cpool;
}

void cj_cp_free(cj_cpool_t *cpool) {

    cj_sfree(cpool->offsets);
    cj_sfree(cpool->types);

    if (cpool->entries != NULL) {
        for (int i = 0; i < cpool->entries_len; ++i) {
            cj_cp_entry_t *entry = cpool->entries[i];
            if (entry == NULL) continue;
            free(entry->data);
            free(entry);
        }
        free(cpool->entries);
    }

    for (int i = 1; i < cpool->length; ++i) {
        if (cpool->cache[i] != NULL) {
            free(cpool->cache[i]);
            cpool->cache[i] = NULL;
        }
    }

    cj_sfree(cpool->classes);
    cj_sfree(cpool->descriptors);


    cj_sfree(cpool->cache);
    cj_sfree(cpool->touched);

    if (cpool->map != NULL) {
        hashmap_destroy(cpool->map);
        cj_sfree(cpool->map);
    }

    free(cpool);
}

const_str cj_cp_get_str(cj_class_t *ctx, u2 idx) {

    cj_cpool_t *cpool = privc(ctx)->cpool;
    if (idx >= cpool->length && cpool->entries == NULL) {
        return NULL;
    }

    //先判断当前条目是否已经被更改，如果已经被更改，则获取被更改后的值
    //如果该索引在原有常量池范围内，则在原有的常量池中查找
    //否则如果索引已经超过了原有常量池的大小，则从新增常量数组中查找.
    if (cpool->length > idx) {
        u2 touched_idx = cpool->touched[idx];
        if (touched_idx != 0) {
            idx = touched_idx;
        }
    }

    if (cpool->length > idx) {
        if (cpool->cache[idx] == NULL) {
            u2 offset = cpool->offsets[idx];
            const_str ptr = privc(ctx)->buf + offset;

            u2 len = cj_ru2(ptr);
            cpool->cache[idx] = malloc(sizeof(char) * (len + 1));
            cpool->cache[idx][len] = 0;
            memcpy(cpool->cache[idx], ptr + 2, len);
        }
        return cpool->cache[idx];
    }

    u2 new_idx = idx - cpool->length;
    if (new_idx >= 0 && new_idx < cpool->entries_len) {
        cj_cp_entry_t *entry = cpool->entries[new_idx];
        if (entry == NULL) return NULL;
        if (entry->tag != CONSTANT_Utf8) return NULL;
        return entry->data;
    }

    return NULL;
}

u4 cj_cp_get_u4(cj_class_t *ctx, u2 idx) {
    u2 offset = privc(ctx)->cpool->offsets[idx];
    return cj_ru4(privc(ctx)->buf + offset);
}

u8 cj_cp_get_u8(cj_class_t *ctx, u2 idx) {
    u2 offset = privc(ctx)->cpool->offsets[idx];
    return cj_ru8(privc(ctx)->buf + offset);
}

int cj_cp_get_int(cj_class_t *ctx, u2 idx) {
    return (int) cj_cp_get_u4(ctx, idx);
}

u2 cj_cp_get_char(cj_class_t *ctx, u2 idx) {
    u4 c = cj_cp_get_u4(ctx, idx);
    return c & 0xffff; /* NOLINT */
}

bool cj_cp_get_bool(cj_class_t *ctx, u2 idx) {
    u4 c = cj_cp_get_u4(ctx, idx);
    return c == 1; /* NOLINT */
}

char cj_cp_get_byte(cj_class_t *ctx, u2 idx) {
    u4 c = cj_cp_get_u4(ctx, idx);
    return c & 0xff; /* NOLINT */
}

long cj_cp_get_long(cj_class_t *ctx, u2 idx) {
    return (long) cj_cp_get_u8(ctx, idx);
}

float cj_cp_get_float(cj_class_t *ctx, u2 idx) {
    int bits = cj_cp_get_int(ctx, idx);
    if (0x7f800000 == bits) {
        return INFINITY;
    } else if (0xff800000 == bits) {
        return -INFINITY;
    } else if ((bits >= 0x7f800001 && bits <= 0x7fffffff) ||
               (bits >= 0xff800001 && bits <= 0xffffffff)) {
        return NAN;
    } else {
        int s = ((bits >> 31) == 0) ? 1 : -1; /* NOLINT */
        int e = ((bits >> 23) & 0xff);        /* NOLINT */
        int m = (e == 0) ?
                (bits & 0x7fffff) << 1 :      /* NOLINT */
                (bits & 0x7fffff) | 0x800000; /* NOLINT */
        float f = s * m * pow(2, e - 150);    /* NOLINT */
        return f;
    }
}

double cj_cp_get_double(cj_class_t *ctx, u2 idx) {
    long bits = cj_cp_get_long(ctx, idx);
    if (0x7ff0000000000000L == bits) {
        return INFINITY;
    } else if (0xfff0000000000000L == bits) {
        return -INFINITY;
    } else if ((bits >= 0x7ff0000000000001L && bits <= 0x7fffffffffffffffL) ||
               (bits >= 0xfff0000000000001L && bits <= 0xffffffffffffffffL)) {
        return NAN;
    } else {
        int s = ((bits >> 63) == 0) ? 1 : -1;                   /* NOLINT */
        int e = (int) ((bits >> 52) & 0x7ffL);                   /* NOLINT */
        long m = (e == 0) ?
                 (bits & 0xfffffffffffffL) << 1 :                /* NOLINT */
                 (bits & 0xfffffffffffffL) | 0x10000000000000L;  /* NOLINT */
        double d = s * m * pow(2, e - 1075);                    /* NOLINT */
        return d;
    }
}

CJ_INTERNAL const_str cj_cp_put_str(cj_class_t *ctx, const_str name, size_t len, u2 *index) {

    //检查当前常量池中是否有该字符串，如果没有，则新建一个
    cj_cpool_t *cpool = privc(ctx)->cpool;
    if (cpool == NULL || cpool->map == NULL) {
        return NULL;
    }

    u2 idx = ((long) hashmap_get(cpool->map, (char *) name, len) & 0xFFFF);
    if (idx == 0) { //不存在
        u2 cur_idx = cpool->entries_len++;
        if (cpool->entries == NULL) {
            cpool->entries = malloc(sizeof(cj_cp_entry_t *));
        } else {
            cpool->entries = realloc(cpool->entries, sizeof(cj_cp_entry_t *) * cpool->entries_len);
        }

        cj_cp_entry_t *entry = malloc(sizeof(cj_cp_entry_t));
        entry->tag = CONSTANT_Utf8;
        entry->len = len;
        entry->data = (unsigned char *) strndup((char *) name, len);

        hashmap_put(cpool->map, (char *) entry->data, entry->len, (void *) (0L + cur_idx + cpool->length));

        if (index != NULL) {
            *index = cur_idx + cpool->length;
        }

        cpool->entries[cur_idx] = entry;
        return entry->data;

    }

    if (index != NULL) {
        *index = idx;
    }

    if (idx < cpool->length) { //当前常量池中已经有该字符串了
        return cpool->cache[idx];
    } else if ((idx - cpool->length) < cpool->entries_len) {
        idx = idx - cpool->length;
        cj_cp_entry_t *entry = cpool->entries[idx];
        return entry->data;
    }

    if (index != NULL) {
        *index = 0;
    }
    return NULL;
}

CJ_INTERNAL const_str cj_cp_put_str2(cj_class_t *ctx, const_str name, size_t len, u2 *index) {
    // 检查现有的常量池中是否有当前字符串
    // 如果有，则直接返回现有的字符串
    // 如果不存在，则将该字符串放置于新的常量池中
    cj_cpool_t *cpool = privc(ctx)->cpool;
    for (int i = 1; i < cpool->length; ++i) {
        u1 type = cpool->types[i];
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
    // 检查cp_entries里是否已存在当前字符串
    // 如果有，则直接返回现有的字符串以及索引值
    for (int i = 0; i < cpool->entries_len; ++i) {
        cj_cp_entry_t *en = cpool->entries[i];
        if (strncmp((char *) en->data, (char *) name, len) == 0) {
            if (index != NULL) *index = i + cpool->length;
            return en->data;
        }
    }

    u2 cur_idx = cpool->entries_len++;
    if (cpool->entries == NULL) {
        cpool->entries = malloc(sizeof(cj_cp_entry_t *));
    } else {
        cpool->entries = realloc(cpool->entries, sizeof(cj_cp_entry_t *) * cpool->entries_len);
    }

    cj_cp_entry_t *entry = malloc(sizeof(cj_cp_entry_t));
    entry->tag = CONSTANT_Utf8;
    entry->len = len;
    entry->data = (unsigned char *) strndup((char *) name, len);

    if (index != NULL) {
        *index = cur_idx + cpool->length;
    }

    cpool->entries[cur_idx] = entry;
    return entry->data;
}

CJ_INTERNAL bool cj_cp_update_str(cj_class_t *ctx, const_str name, size_t len, u2 index) {

    u2 new_idx = 0;
    cj_cp_put_str(ctx, name, len, &new_idx);
    if (new_idx == index) {
        return false; //nothing changed
    }

    cj_cpool_t *cpool = privc(ctx)->cpool;
    cpool->touched[index] = new_idx;

    return true;
}

CJ_INTERNAL bool cj_cp_update_class(cj_class_t *ctx, u2 idx, u2 name_idx) {
    //todo check
    cj_cpool_t *cpool = privc(ctx)->cpool;
    u4 offset = cpool->offsets[idx];
    cj_wu2(privc(ctx)->buf + offset, name_idx);
    return true;
}

u4 cj_cp_get_tail_offset(cj_cpool_t *ctx) {
    return ctx->tail_offset;
}

void cj_cp_add_descriptor_idx(cj_cpool_t *cpool, u2 desc_idx) {
    cpool->descriptors[cpool->descriptors_len++] = desc_idx;
}

u2 cj_cp_get_descriptor_idx(cj_cpool_t *cpool, u2 idx) {
    return cpool->descriptors[idx];
}

u2 cj_cp_get_descriptor_count(cj_cpool_t *cpool) {
    return cpool->descriptors_len;
}

u2 cj_cp_get_class_idx(cj_cpool_t *cpool, u2 idx) {
    return cpool->classes[idx];
}

u2 cj_cp_get_class_count(cj_cpool_t *cpool) {
    return cpool->classes_len;
}

CJ_INTERNAL u2 cj_cp_get_u2(cj_class_t *ctx, u2 idx) {
    u4 offset = privc(ctx)->cpool->offsets[idx];
    return cj_ru2(privc(ctx)->buf + offset);
}

u2 cj_cp_get_length(cj_cpool_t *cpool) {
    return cpool->length;
}

u2 cj_cp_get_str_index(cj_class_t *ctx, const_str str) {
    cj_cpool_t *cpool = privc(ctx)->cpool;

    long idx = (long) hashmap_get(cpool->map, (char *) str, strlen((char *) str));
    if (idx == 0) {
        return 0;
    }

    return idx & 0xFFFF;
}

