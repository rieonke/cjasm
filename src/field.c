//
// Created by Rieon Ke on 2020/7/23.
//

#include <limits.h>
#include <assert.h>
#include "util.h"
#include "field.h"
#include "hashmap.h"
#include "annotation.h"
#include "attribute.h"
#include "cpool.h"
#include "class.h"
#include "mem_buf.h"

#define priv(f) ((cj_field_priv_t*)(f->priv))

typedef struct cj_field_priv_s cj_field_priv_t;
struct cj_field_priv_s {
    u4 dirty;
    u4 head;
    u4 tail;
    bool annotation_set_initialized;
    cj_annotation_group_t *annotation_group;
    cj_attribute_group_t *attribute_group;
};


#define cj_field_init_annotation_group(field) \
    if (!priv(field)->annotation_set_initialized) \
        priv(field)->annotation_set_initialized = cj_annotation_group_init(field->klass, priv(field)->attribute_group, &priv(field)->annotation_group)


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
    if (ctx == NULL || group == NULL || field == NULL) return false;

    //check if name already exists
    cj_field_t *f = cj_field_group_get_by_name(ctx, group, field->name);
    if (f != NULL) {
        return false;
    }

    if (field->priv == NULL) {
        field->priv = malloc(sizeof(cj_field_priv_t));
        priv(field)->dirty = CJ_DIRTY_NEW;
        priv(field)->annotation_set_initialized = false;
        priv(field)->attribute_group = NULL;
        priv(field)->annotation_group = NULL;
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
        buf_ptr buf = cj_class_get_buf_ptr(ctx, 0);
        for (int i = 0; i < set->count; ++i) {
            u4 offset = set->heads[i];
            u2 name_index = cj_ru2(buf + offset + 2);
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
        buf_ptr buf_ptr = cj_class_get_buf_ptr(ctx, head);
        u2 access_flags = cj_ru2(buf_ptr);
        u2 name_index = cj_ru2(buf_ptr + 2);
        u2 descriptor_index = cj_ru2(buf_ptr + 4);
        u2 attributes_count = cj_ru2(buf_ptr + 6);

        cj_field_t *field = malloc(sizeof(cj_field_t));
        field->access_flags = access_flags;
        field->index = idx;
        field->klass = ctx;
        field->name = cj_cp_get_str(ctx, name_index);
        field->descriptor = cj_cp_get_str(ctx, descriptor_index);
        field->attribute_count = attributes_count;
        field->priv = calloc(1, sizeof(cj_field_priv_t));
        priv(field)->head = head;
        priv(field)->tail = tail;
        priv(field)->dirty = CJ_DIRTY_CLEAN;
        priv(field)->attribute_group = cj_class_get_field_attribute_group(ctx, idx);
        priv(field)->annotation_group = NULL;
        priv(field)->annotation_set_initialized = false;

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

CJ_INTERNAL void cj_field_free(cj_field_t *field) {
    if (field == NULL) {
        return;
    }
    if (priv(field) != NULL && priv(field)->annotation_group != NULL) {
        cj_annotation_group_free(priv(field)->annotation_group);
    }

    if (priv(field)->dirty & CJ_DIRTY_NEW) {
        cj_sfree((char *) field->name);
        cj_sfree((char *) field->descriptor);
    }


    cj_sfree(priv(field));
    cj_sfree(field);
}


cj_field_t *cj_field_new(cj_class_t *ctx, u2 access_flags, const_str name, const_str descriptor) {

    cj_field_t *field = malloc(sizeof(cj_field_t));
    field->klass = ctx;
    field->access_flags = access_flags;
    field->name = (const_str) strdup((char *) name);
    field->descriptor = (const_str) strdup((char *) descriptor);

    cj_field_priv_t *priv = malloc(sizeof(cj_field_priv_t));
    priv->dirty = CJ_DIRTY_NEW;
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

cj_modifiers_t cj_field_get_modifiers(cj_field_t *field) {
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
        priv(field)->attribute_group == NULL ||
        idx >= priv(field)->attribute_group->count) {
        return NULL;
    }
    return cj_attribute_group_get(field->klass, priv(field)->attribute_group, idx);
}

u2 cj_field_get_annotation_count(cj_field_t *field) {

    if (field == NULL ||
        priv(field) == NULL ||
        field->klass == NULL ||
        field->attribute_count <= 0) {
        return 0;
    }

    if (priv(field)->annotation_group == NULL && !priv(field)->annotation_set_initialized) {
        bool init = cj_annotation_group_init(field->klass, priv(field)->attribute_group,
                                             &priv(field)->annotation_group);
        priv(field)->annotation_set_initialized = init;
    }

    if (priv(field)->annotation_group == NULL) return 0;
    return priv(field)->annotation_group->count;
}

cj_annotation_t *cj_field_get_annotation(cj_field_t *field, u2 idx) {
    if (field == NULL ||
        priv(field) == NULL ||
        field->klass == NULL) {
        return NULL;
    }

    cj_field_init_annotation_group(field);

    return cj_annotation_group_get(field->klass, priv(field)->annotation_group, idx);
}


bool cj_field_set_name(cj_field_t *field, const_str name) {
    if (field == NULL || field->klass == NULL || name == NULL) return false;

    if (cj_streq(name, field->name)) {
        return false;
    }

    u2 idx = 0;
    const_str new_name = cj_cp_put_str(field->klass, name, strlen((char *) name), &idx);
    field->name = new_name;

    //make dirty
    priv(field)->dirty = CJ_DIRTY_NAME;

    return true;
}

bool cj_field_add_annotation(cj_field_t *field, cj_annotation_t *ann) {
    if (field == NULL || priv(field) == NULL) return false;

    cj_annotation_group_init_or_create(field, ann->visible);
    if (cj_annotation_group_add(field->klass, priv(field)->annotation_group, ann)) {
        cj_field_mark_dirty(field, CJ_DIRTY_ATTR);
        return true;
    }
    return false;
}

cj_annotation_group_t *cj_field_get_annotation_group(cj_field_t *field) {
    if (field == NULL || priv(field) == NULL) return NULL;

    cj_field_init_annotation_group(field);
    return priv(field)->annotation_group;
}

cj_attribute_group_t *cj_field_get_attribute_group(cj_field_t *field) {
    if (field == NULL || priv(field) == NULL) return NULL;
    return priv(field)->attribute_group;
}

void cj_field_mark_dirty(cj_field_t *field, u4 flag) {
    priv(field)->dirty |= flag;
}


void cj_field_mark_removed(cj_field_t *field) {
    priv(field)->dirty |= CJ_DIRTY_REMOVE;
}

bool cj_field_remove_annotation(cj_field_t *field, u2 index) {
    if (field == NULL || priv(field) == NULL) return false;

    cj_field_init_annotation_group(field);

    if (cj_annotation_group_remove(field->klass, priv(field)->annotation_group, index)) {
        cj_field_mark_dirty(field, CJ_DIRTY_ATTR);
    }
    return false;
}

bool cj_field_write_buf(cj_field_t *field, cj_mem_buf_t *buf) {
    if (field == NULL || priv(field) == NULL) return false;

    /*
     field_info {
        u2             access_flags;
        u2             name_index;
        u2             descriptor_index;
        u2             attributes_count;
        attribute_info attributes[attributes_count];
     }
     */

    if (priv(field)->dirty & CJ_DIRTY_REMOVE) { //已被删除
        return false;
    } else if (priv(field)->dirty == CJ_DIRTY_CLEAN) {
        u4 head = priv(field)->head;
        u4 tail = priv(field)->tail;
        if (head >= tail) {
            return false;
        }

        buf_ptr buf_ptr = cj_class_get_buf_ptr(field->klass, 0);
        cj_mem_buf_write_str(buf, (char *) buf_ptr + head, tail - head);
    } else if (priv(field)->dirty != CJ_DIRTY_CLEAN) {
        cj_mem_buf_write_u2(buf, field->access_flags);
        u2 name_idx = 0;
        u2 descriptor_idx = 0;

        cj_cp_put_str(field->klass, field->name, strlen((char *) field->name), &name_idx);
        cj_cp_put_str(field->klass, field->descriptor, strlen((char *) field->descriptor), &descriptor_idx);

        cj_mem_buf_write_u2(buf, name_idx);
        cj_mem_buf_write_u2(buf, descriptor_idx);

        cj_attribute_group_t *attr_group = cj_field_get_attribute_group(field);
        if (attr_group == NULL) {
            cj_mem_buf_write_u2(buf, 0);
        } else {
            bool attr_st = cj_attribute_group_write_buf(field->klass, attr_group, buf);
            if (!attr_st) {
                cj_debug("field %s does not have any attributes\n", field->name);
            }
        }
    }

    return true;
}
