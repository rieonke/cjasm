//
// Created by Rieon Ke on 2020/7/23.
//

#include <limits.h>
#include "field.h"
#include "hashmap.h"


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
