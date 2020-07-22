//
// Created by Rieon Ke on 2020/7/21.
//

#include <math.h>
#include "cpool.h"

#define CJ_BUFFER_SIZE 1024

cj_buf_t *cj_cp_to_buf(cj_class_t *ctx) {

    //copy original buf
    u1 *original_buf = NULL;
    u4 original_cp_len = privc(ctx)->header - 10;
    cj_cpool_t *cpool = privc(ctx)->cpool;
    u2 cp_size = cpool->length;
    original_buf = malloc(sizeof(u1) * (original_cp_len + 2));
    memcpy(original_buf + 2, privc(ctx)->buf + 10, original_cp_len);
    u4 cp_len = original_cp_len + 2;

    char buffer[CJ_BUFFER_SIZE] = {0};
    int buffer_pos = 0;

#define move() \
      original_buf = realloc(original_buf, (cp_len+ buffer_pos) * sizeof(u1)); \
      memcpy(original_buf + cp_len,buffer,buffer_pos);         \
      cp_len+=buffer_pos;                                                    \
      buffer_pos = 0;

    //generate new buf
    for (int i = 0; i < cpool->entries_len; ++i) {
        //fixme 检查buffer是否已满
        cj_cp_entry_t *entry = cpool->entries[i];
        if (buffer_pos >= CJ_BUFFER_SIZE - 1) {
            move()
        }

        buffer[buffer_pos++] = entry->tag;
        if (entry->tag == CONSTANT_Utf8) {
            cp_size++;

            cj_wu2(buffer + buffer_pos, entry->len);
            buffer_pos += 2;

            //如果字符串长度大于缓冲区长度，则分批拷贝
            u2 len = 0;
            while (len < entry->len) {
                u2 available = CJ_BUFFER_SIZE - buffer_pos;
                u2 copy_len = entry->len - len < available ? entry->len - len : available;

                memcpy(buffer + buffer_pos, entry->data + len, copy_len);
                buffer_pos += copy_len;
                len += copy_len;
                move()
            }
        }
    }

    *(u2 *) (original_buf) = btol16(cp_size);
    cj_buf_t *buf = malloc(sizeof(cj_buf_t));
    buf->length = cp_len;
    buf->buf = original_buf;

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

    int cur_cp_idx = 1;
    u4 cur_cp_offset = 10;
    while (cur_cp_idx < cp_len) {

        int cp_size;
        enum cj_cp_type type = (enum cj_cp_type) cj_ru1(buf + cur_cp_offset++);

        *(cp_types + cur_cp_idx) = type;
        *(cp_offsets + cur_cp_idx) = cur_cp_offset;
        cur_cp_idx++;
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
            case CONSTANT_Class:
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
                cp_size = 2 + cj_ru2(buf + cur_cp_offset);
                break;
            }
            default:
                fprintf(stderr, "ERROR: invalid class format, unrecognized cp entry tag: %d\n", type);
                free(cp_offsets);
                return NULL;
        }
        //设置当前常量的截止位置
        cur_cp_offset += cp_size;
    }


    cj_cpool_t *cpool = malloc(sizeof(cj_cpool_t));
    cpool->length = cp_len;
    cpool->types = cp_types;
    cpool->cache = calloc(cp_len, sizeof(unsigned char *));
    cpool->touched = calloc(cp_len, sizeof(u4));
    cpool->offsets = cp_offsets;
    cpool->entries = NULL;
    cpool->entries_len = 0;
    cpool->tail_offset = cur_cp_offset;
    cpool->descriptors = descriptors;
    cpool->descriptors_len = descriptors_len;
    return cpool;
}

void cj_cp_free(cj_cpool_t *cpool) {

    if (cpool->entries != NULL) {
        for (int i = 0; i < cpool->entries_len; ++i) {
            cj_cp_entry_t *entry = cpool->entries[i];
            if (entry == NULL) continue;
            free(entry->data);
            free(entry);
        }
        free(cpool->entries);
    }

    for (int i = 0; i < cpool->length; ++i) {
        if (cpool->cache[i] != NULL) {
            free(cpool->cache[i]);
            cpool->cache[i] = NULL;
        }
    }
    cj_sfree(cpool->cache);
    cj_sfree(cpool->touched);

    free(cpool);
}

const_str cj_cp_get_str(cj_class_t *ctx, u2 idx) {

    cj_cpool_t *cpool = privc(ctx)->cpool;
    if (idx >= cpool->length && cpool->entries == NULL) {
        return NULL;
    }

    //如果该索引在原有常量池范围内，则在原有的常量池中查找
    //否则如果索引已经超过了原有常量池的大小，则从新增常量数组中查找.

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

CJ_INTERNAL bool cj_cp_update_str(cj_class_t *ctx, const_str name, size_t len, u2 *index) {
    return false;
}

CJ_INTERNAL bool cj_cp_update_class(cj_class_t *ctx, u2 idx, u2 name_idx) {
    //todo check
    cj_cpool_t *cpool = privc(ctx)->cpool;
    u4 offset = cpool->offsets[idx];
    cj_wu2(privc(ctx)->buf + offset, name_idx);
    return true;
}

