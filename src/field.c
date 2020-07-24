//
// Created by Rieon Ke on 2020/7/23.
//

#include <limits.h>
#include "field.h"
#include "hashmap.h"
#include "annotation.h"
#include "attribute.h"
#include "cpool.h"


cj_field_group_t *cj_field_group_new(u2 count, u4 *offsets) {
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
    group->offsets = offsets;
    group->fetched = calloc(count, sizeof(cj_field_t *));
    group->map = map;

    return group;
}


cj_field_t *cj_field_group_get_by_name(cj_class_t *ctx, cj_field_group_t *set, const_str name) {

    if (set == NULL || set->count <= 0 || set->map == NULL) return NULL;

    if (hashmap_num_entries(set->map) == 0) {
        //initialize map
        for (int i = 0; i < set->count; ++i) {
            u4 offset = set->offsets[i];
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
        u4 offset = set->offsets[idx];
        u2 access_flags = cj_ru2(privc(ctx)->buf + offset);
        u2 name_index = cj_ru2(privc(ctx)->buf + offset + 2);
        u2 descriptor_index = cj_ru2(privc(ctx)->buf + offset + 4);
        u2 attributes_count = cj_ru2(privc(ctx)->buf + offset + 6);

        cj_field_t *field = malloc(sizeof(cj_field_t));
        field->access_flags = access_flags;
        field->index = idx;
        field->klass = ctx;
        field->name = cj_cp_get_str(ctx, name_index);
        field->descriptor = cj_cp_get_str(ctx, descriptor_index);
        field->attribute_count = attributes_count;
        field->priv = calloc(1, sizeof(cj_field_priv_t));
        privf(field)->offset = offset;
        privf(field)->attribute_set = privc(ctx)->field_attribute_sets[idx];
        privf(field)->annotation_set = NULL;
        privf(field)->annotation_set_initialized = false;

        set->fetched[idx] = field;
    }

    return set->fetched[idx];

}

CJ_INTERNAL void cj_field_set_free(cj_field_group_t *set) {

    if (set == NULL) return;
    cj_sfree(set->offsets);
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
    return NULL;
}

CJ_INTERNAL void cj_field_free(cj_field_t *field) {
    if (field == NULL) {
        return;
    }
    if (privf(field) != NULL && privf(field)->annotation_set != NULL) {
        cj_annotation_group_free(privf(field)->annotation_set);
    }
    cj_sfree(privf(field));
    cj_sfree(field);
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
        privf(field)->attribute_set == NULL ||
        idx >= privf(field)->attribute_set->count) {
        return NULL;
    }
    return cj_attribute_group_get(field->klass, privf(field)->attribute_set, idx);
}

u2 cj_field_get_annotation_count(cj_field_t *field) {

    if (field == NULL ||
        privf(field) == NULL ||
        field->klass == NULL ||
        field->attribute_count <= 0) {
        return 0;
    }

    if (privf(field)->annotation_set == NULL && !privf(field)->annotation_set_initialized) {
        bool init = cj_annotation_group_init(field->klass, privf(field)->attribute_set, &privf(field)->annotation_set);
        privf(field)->annotation_set_initialized = init;
    }

    if (privf(field)->annotation_set == NULL) return 0;
    return privf(field)->annotation_set->count;
}

cj_annotation_t *cj_field_get_annotation(cj_field_t *field, u2 idx) {
    if (field == NULL ||
        privf(field) == NULL ||
        field->klass == NULL) {
        return NULL;
    }

    if (privf(field)->annotation_set == NULL && !privf(field)->annotation_set_initialized) {
        bool init = cj_annotation_group_init(field->klass, privf(field)->attribute_set, &privf(field)->annotation_set);
        privf(field)->annotation_set_initialized = init;
    }

    return cj_annotation_group_get(field->klass, privf(field)->annotation_set, idx);
}


void cj_field_set_name(cj_field_t *field, const_str name) {
    u2 idx = 0;
    const_str new_name = cj_cp_put_str(field->klass, name, strlen((char *) name), &idx);
    field->name = new_name;
}
