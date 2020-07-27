//
// Created by Rieon Ke on 2020/7/23.
//

#include <limits.h>
#include "field.h"
#include "hashmap.h"
#include "annotation.h"
#include "attribute.h"
#include "cpool.h"

#define CJ_FIELD_D_NEW 0x2


cj_field_group_t *cj_field_group_new(u2 count, u4 *offsets, u4 *tails) {
    if (count == 0 || offsets == NULL) return NULL;

    u2 mv = count;
    cj_n2pow(mv);

    struct hashmap_s *map = malloc(sizeof(struct hashmap_s));
    if (hashmap_create(mv, map) != 0) {
        //error
        free(map);
        return NULL;
    }
    cj_field_group_t *group = malloc(sizeof(cj_field_group_t));
    group->count = count;
    group->heads = offsets;
    group->fetched = calloc(count, sizeof(cj_field_t *));
    group->map = map;
    group->tails = tails;

    return group;
}

bool cj_field_group_add(cj_class_t *ctx, cj_field_group_t *group, cj_field_t *field) {
    if (ctx == NULL || privc(ctx) == NULL || group == NULL || field == NULL) return false;

    //check if name already exists
    cj_field_t *f = cj_field_group_get_by_name(ctx, group, field->name);
    if (f != NULL) {
        return false;
    }

    if (field->priv == NULL) {
        field->priv = malloc(sizeof(cj_field_priv_t));
        privf(field)->dirty = CJ_FIELD_D_NEW;
        privf(field)->annotation_set_initialized = false;
        privf(field)->attribute_group = NULL;
        privf(field)->annotation_group = NULL;
    }

    group->fetched = realloc(group->fetched, sizeof(cj_field_t *) * ++group->count);
    group->fetched[group->count - 1] = field;
    hashmap_put(group->map, (char *) field->name, strlen((char *) field->name), (void *) (0L + group->count));
//    ctx->field_count = group->count;

    return true;
}

cj_field_t *cj_field_group_get_by_name(cj_class_t *ctx, cj_field_group_t *set, const_str name) {

    if (set == NULL || set->count <= 0 || set->map == NULL) return NULL;

    if (hashmap_num_entries(set->map) == 0) {
        //initialize map
        for (int i = 0; i < set->count; ++i) {
            u4 offset = set->heads[i];
            u2 name_index = cj_ru2(privc(ctx)->buf + offset + 2);
            const_str name_str = cj_cp_get_str(ctx, name_index);
            hashmap_put(set->map, (char *) name_str, strlen((char *) name_str), (void *) (1L + i));
        }
    }

    long idx = (long) hashmap_get(set->map, (char *) name, strlen((char *) name));
    if (idx == 0) {
        return NULL;
    }

    return cj_field_group_get(ctx, set, (idx - 1) & 0xFFFF);
}

CJ_INTERNAL cj_field_t *cj_field_group_get(cj_class_t *ctx, cj_field_group_t *set, u2 idx) {

    if (set->fetched == NULL) {
        //初始化字段缓存
        set->fetched = calloc(sizeof(cj_field_t *), ctx->field_count);
    }

    if (set->fetched[idx] == NULL) {
        //按需初始化字段，并放入缓存中.
        u4 head = set->heads[idx];
        u4 tail = set->tails[idx];
        u2 access_flags = cj_ru2(privc(ctx)->buf + head);
        u2 name_index = cj_ru2(privc(ctx)->buf + head + 2);
        u2 descriptor_index = cj_ru2(privc(ctx)->buf + head + 4);
        u2 attributes_count = cj_ru2(privc(ctx)->buf + head + 6);

        cj_field_t *field = malloc(sizeof(cj_field_t));
        field->access_flags = access_flags;
        field->index = idx;
        field->klass = ctx;
        field->name = cj_cp_get_str(ctx, name_index);
        field->descriptor = cj_cp_get_str(ctx, descriptor_index);
        field->attribute_count = attributes_count;
        field->priv = calloc(1, sizeof(cj_field_priv_t));
        privf(field)->head = head;
        privf(field)->tail = tail;
        privf(field)->dirty = 0;
        privf(field)->attribute_group = privc(ctx)->field_attribute_groups[idx];
        privf(field)->annotation_group = NULL;
        privf(field)->annotation_set_initialized = false;

        set->fetched[idx] = field;
    }

    return set->fetched[idx];

}

CJ_INTERNAL void cj_field_set_free(cj_field_group_t *set) {

    if (set == NULL) return;
    cj_sfree(set->heads);
    cj_sfree(set->tails);
    if (set->fetched != NULL) {
        for (int i = 0; i < set->count; ++i) {
            cj_field_free(set->fetched[i]);
        }
    }
    cj_sfree(set->fetched);
    hashmap_destroy(set->map);
    cj_sfree(set->map);
    cj_sfree(set);
}

cj_mem_buf_t *cj_field_to_buf(cj_field_t *field) {
    if (field == NULL || privf(field) == NULL) return NULL;

    if (privf(field)->dirty & 0x8000) { //已被删除
        return NULL;
    }

    cj_mem_buf_t *buf = NULL;

    if (privf(field)->dirty == 0) {
        u4 head = privf(field)->head;
        u4 tail = privf(field)->tail;
        if (head >= tail) {
            return NULL;
        }

        buf = cj_mem_buf_new();
        cj_mem_buf_write_str(buf, (char *) privc(field->klass)->buf + head, tail - head);
        return buf;
    }
    /*
     field_info {
        u2             access_flags;
        u2             name_index;
        u2             descriptor_index;
        u2             attributes_count;
        attribute_info attributes[attributes_count];
     }
     */

    if (privf(field)->dirty & CJ_FIELD_D_NEW) {
        buf = cj_mem_buf_new();
        cj_mem_buf_write_u2(buf, field->access_flags);
        u2 name_idx = 0;
        u2 descriptor_idx = 0;

        cj_cp_put_str(field->klass, field->name, strlen((char *) field->name), &name_idx);
        cj_cp_put_str(field->klass, field->descriptor, strlen((char *) field->descriptor), &descriptor_idx);

        cj_mem_buf_write_u2(buf, name_idx);
        cj_mem_buf_write_u2(buf, descriptor_idx);
        cj_mem_buf_write_u2(buf, 0);
    }

    if (buf != NULL) cj_mem_buf_flush(buf);
    return buf;
}

CJ_INTERNAL void cj_field_free(cj_field_t *field) {
    if (field == NULL) {
        return;
    }
    if (privf(field) != NULL && privf(field)->annotation_group != NULL) {
        cj_annotation_group_free(privf(field)->annotation_group);
    }
    cj_sfree(privf(field));
    cj_sfree(field);
}


cj_field_t *cj_field_new(cj_class_t *ctx, u2 access_flags, const_str name, const_str descriptor) {

    cj_field_t *field = malloc(sizeof(cj_field_t));
    field->klass = ctx;
    field->access_flags = access_flags;
    field->name = (const_str) strdup((char *) name);
    field->descriptor = (const_str) strdup((char *) descriptor);

    cj_field_priv_t *priv = malloc(sizeof(cj_field_priv_t));
    priv->dirty = CJ_FIELD_D_NEW;
    priv->head = 0;
    priv->tail = 0;
    priv->annotation_set_initialized = false;
    priv->attribute_group = NULL;
    priv->annotation_group = NULL;

    field->priv = priv;
    return field;
}

const_str cj_field_get_name(cj_field_t *field) {
    return field->name;
}

u2 cj_field_get_access_flags(cj_field_t *field) {
    return field->access_flags;
}

const_str cj_field_get_descriptor(cj_field_t *field) {
    return field->descriptor;
}

u2 cj_field_get_attribute_count(cj_field_t *field) {
    return field->attribute_count;
}

cj_attribute_t *cj_field_get_attribute(cj_field_t *field, u2 idx) {
    if (field->klass == NULL ||
        field->attribute_count <= 0 ||
        privf(field)->attribute_group == NULL ||
        idx >= privf(field)->attribute_group->count) {
        return NULL;
    }
    return cj_attribute_group_get(field->klass, privf(field)->attribute_group, idx);
}

u2 cj_field_get_annotation_count(cj_field_t *field) {

    if (field == NULL ||
        privf(field) == NULL ||
        field->klass == NULL ||
        field->attribute_count <= 0) {
        return 0;
    }

    if (privf(field)->annotation_group == NULL && !privf(field)->annotation_set_initialized) {
        bool init = cj_annotation_group_init(field->klass, privf(field)->attribute_group,
                                             &privf(field)->annotation_group);
        privf(field)->annotation_set_initialized = init;
    }

    if (privf(field)->annotation_group == NULL) return 0;
    return privf(field)->annotation_group->count;
}

cj_annotation_t *cj_field_get_annotation(cj_field_t *field, u2 idx) {
    if (field == NULL ||
        privf(field) == NULL ||
        field->klass == NULL) {
        return NULL;
    }

    if (privf(field)->annotation_group == NULL && !privf(field)->annotation_set_initialized) {
        bool init = cj_annotation_group_init(field->klass, privf(field)->attribute_group,
                                             &privf(field)->annotation_group);
        privf(field)->annotation_set_initialized = init;
    }

    return cj_annotation_group_get(field->klass, privf(field)->annotation_group, idx);
}


void cj_field_set_name(cj_field_t *field, const_str name) {
    u2 idx = 0;
    const_str new_name = cj_cp_put_str(field->klass, name, strlen((char *) name), &idx);
    field->name = new_name;
}
