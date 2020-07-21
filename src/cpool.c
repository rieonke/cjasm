//
// Created by Rieon Ke on 2020/7/21.
//

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

