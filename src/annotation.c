//
// Created by Rieon Ke on 2020/7/23.
//

#include "util.h"
#include "cpool.h"
#include "class.h"
#include "annotation.h"
#include "attribute.h"

#define CJ_ANN_D_NEW 0x2

typedef struct cj_annotation_priv_s cj_annotation_priv_t;
struct cj_annotation_priv_s {
    u4 dirty;
    u4 head;
    u4 length;
};

#define priv(a) ((cj_annotation_priv_t*)(a->priv))

CJ_INTERNAL cj_annotation_t *cj_annotation_parse(cj_class_t *ctx, buf_ptr attr_ptr, u4 *out_offset) {

    u4 offset = out_offset == NULL ? 0 : *out_offset;
    cj_annotation_t *annotation = NULL;
    cj_element_pair_t **pairs = NULL;
    cj_annotation_priv_t *priv = NULL;
    u4 head = offset;
    u4 length;

    /*
      annotation {
          u2 type_index;
          u2 num_element_value_pairs;
          {   u2            element_name_index;
              element_value value;
          } element_value_pairs[num_element_value_pairs];
      }

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

    length = offset - head;

    priv = malloc(sizeof(cj_annotation_priv_t));
    priv->head = head;
    priv->length = length;
    priv->dirty = 0;

    annotation = malloc(sizeof(cj_annotation_t));
    annotation->type_name = cj_cp_get_str(ctx, type_index);
    annotation->attributes_count = num_pairs;
    annotation->attributes = pairs;
    annotation->priv = priv;

    if (out_offset != NULL) *out_offset = offset;
    return annotation;
}

CJ_INTERNAL cj_element_t *cj_annotation_parse_element_value(cj_class_t *ctx, buf_ptr ev_ptr, u4 *out_offset) {

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
        case 'S': /*short*/
        case 'Z': /*boolean*/
        case 'B': /*byte*/
        case 'C': /*char*/
        case 'I': /*int*/
        {
            u2 idx = cj_ru2(ev_ptr + offset);
            int val = cj_cp_get_int(ctx, idx);
            ev->const_num = val;
            offset += 2;
            break;
        }
        case 'F': /*float*/
        {
            u2 idx = cj_ru2(ev_ptr + offset);
            float val = cj_cp_get_float(ctx, idx);
            ev->const_num = val;
            offset += 2;
            break;
        }
        case 'D': /*double*/
        {
            u2 idx = cj_ru2(ev_ptr + offset);
            double val = cj_cp_get_double(ctx, idx);
            ev->const_num = val;
            offset += 2;
            break;
        }
        case 'J': /*long*/
        {
            u2 idx = cj_ru2(ev_ptr + offset);
            long val = cj_cp_get_long(ctx, idx);
            ev->const_num = val;
            offset += 2;
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
            break;
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

CJ_INTERNAL void cj_annotation_group_free(cj_annotation_group_t *set) {
    if (set == NULL) return;
    if (set->cache != NULL) {
        for (int i = 0; i < set->count; ++i) {
            cj_annotation_free(set->cache[i]);
        }
        cj_sfree(set->cache);
    }

    cj_sfree(set->offsets);
    cj_sfree(set);
}

CJ_INTERNAL void cj_element_free(cj_element_t *element) {
    if (element == NULL) return;
    switch (element->tag) {
        case '@': /*annotation*/
            cj_annotation_free(element->annotation);
            break;
        case '[': /*array*/
            if (element->elements != NULL) {
                for (int i = 0; i < element->element_count; ++i) {
                    cj_element_free(element->elements[i]);
                }
                cj_sfree(element->elements);
            }
        default:
            break;
    }

    cj_sfree(element);
}

CJ_INTERNAL void cj_annotation_free(cj_annotation_t *ann) {
    if (ann == NULL) return;

    if (ann->attributes != NULL) {

        for (int i = 0; i < ann->attributes_count; ++i) {
            cj_element_pair_t *pair = ann->attributes[i];
            if (pair == NULL) continue;
            cj_element_free(pair->value);
            cj_sfree(pair);
        }
        cj_sfree(ann->attributes);
    }
    cj_sfree(ann->priv);
    cj_sfree(ann);


}

cj_annotation_t *cj_annotation_group_get(cj_class_t *ctx, cj_annotation_group_t *set, u2 idx) {
    if (set == NULL || set->cache == NULL || idx >= set->count) {
        return NULL;
    }

    return set->cache[idx];
}

CJ_INTERNAL bool
cj_annotation_group_init(cj_class_t *ctx, cj_attribute_group_t *attr_set, cj_annotation_group_t **set) {

    cj_annotation_group_t *ann_group = NULL;
    u2 ann_count = 0;
    buf_ptr buf_ptr = cj_class_get_buf_ptr(ctx, 0);

    for (int i = 0; i < attr_set->count; ++i) {
        cj_attribute_t *attr = cj_attribute_group_get(ctx, attr_set, i);
        u4 offset = cj_attribute_get_head_offset(attr);//priva(attr)->offset;

        if (attr == NULL) {
            continue; //fixme: error handling
        }

        bool parse = false;
        bool visible = false;
        if (attr->type == CJ_ATTR_RuntimeInvisibleAnnotations) {
            parse = true;
            visible = false;
        } else if (attr->type == CJ_ATTR_RuntimeVisibleAnnotations) {
            parse = true;
            visible = true;
        }

        if (parse) {

            u2 num_annotations = cj_ru2(buf_ptr + offset + 6);
            offset += 8;

            if (ann_group == NULL) {
                ann_group = malloc(sizeof(cj_annotation_group_t));
                ann_group->count = num_annotations;
                ann_group->offsets = malloc(sizeof(u4) * ann_group->count);
                ann_group->cache = malloc(sizeof(cj_annotation_t *) * ann_group->count);
            } else {
                ann_group->count += num_annotations;
                ann_group->offsets = realloc(ann_group->offsets, sizeof(u4) * ann_group->count);
                ann_group->cache = realloc(ann_group->cache, sizeof(cj_annotation_t *) * ann_group->count);
            }

            for (int j = 0; j < num_annotations; ++j) {
                ann_group->offsets[ann_count] = offset;

                cj_annotation_t *ann = cj_annotation_parse(ctx, buf_ptr, &offset);
                ann->visible = visible;

                ann_group->cache[ann_count] = ann;
                ++ann_count;
            }
            if (visible)
                ann_group->vi_attr = attr;
            else
                ann_group->in_attr = attr;
            cj_attribute_set_data(attr, ann_group);
        }
    }

    *set = ann_group;
    return true;
}

cj_annotation_t *cj_annotation_new(const_str type, bool visible) {

    cj_annotation_priv_t *priv = malloc(sizeof(cj_annotation_priv_t));
    priv->dirty = CJ_ANN_D_NEW;
    priv->head = 0;

    cj_annotation_t *ann = malloc(sizeof(cj_annotation_t));
    ann->type_name = type; //todo
    ann->visible = visible;
    ann->attributes_count = 0;
    ann->attributes = NULL;
    ann->priv = priv;

    return ann;
}

bool cj_annotation_group_add(cj_class_t *cls, cj_annotation_group_t *group, cj_annotation_t *ann) {
    if (cls == NULL || group == NULL || ann == NULL) return false;

    group->cache = realloc(group->cache, sizeof(cj_annotation_t *) * ++group->count);
    group->cache[group->count - 1] = ann;
    if (ann->visible)
        cj_attribute_mark_dirty(group->vi_attr);
    else
        cj_attribute_mark_dirty(group->in_attr);

    return 0;
}

cj_mem_buf_t *cj_annotation_group_to_buf(cj_class_t *cls, cj_annotation_group_t *group, bool visible) {

    if (cls == NULL || group == NULL) return NULL;

    cj_mem_buf_t *buf = cj_mem_buf_new();

    cj_mem_buf_write_u2(buf, /*annotations count*/0);
    u2 ann_count = 0;
    for (int i = 0; i < group->count; ++i) {
        cj_annotation_t *ann = cj_annotation_group_get(cls, group, i);
        if (ann == NULL) continue;
        if (ann->visible == visible) {
            cj_mem_buf_t *ann_buf = cj_annotation_to_buf(cls, ann);
            if (ann_buf == NULL) continue;
            cj_mem_buf_write_buf(buf, ann_buf);
            cj_mem_buf_free(ann_buf);
            ++ann_count;
        }
    }

    cj_mem_buf_flush(buf);
    cj_wu2(buf->data, ann_count);
    return buf;
}

void cj_annotation_write_element_value(cj_class_t *cls, cj_element_t *p, cj_mem_buf_t *buf) {
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

    cj_element_t *value = p;
    cj_mem_buf_write_u1(buf, value->tag);

    switch (value->tag) {
        case 'S': /*short*/
        case 'Z': /*boolean*/
        case 'B': /*byte*/
        case 'C': /*char*/
        case 'I': /*int*/
        case 'F': /*float*/
        {
            u2 idx = cj_cp_put_u4(cls, value->const_num & 0xFFFFFFFF);
            cj_mem_buf_write_u2(buf, idx);
            break;
        }
        case 'D': /*double*/
        case 'J': /*long*/
        {
            u2 idx = cj_cp_put_u8(cls, value->const_num);
            cj_mem_buf_write_u2(buf, idx);
            break;
        }
        case 's':/*string*/
        {
            u2 idx = 0;
            cj_cp_put_str(cls, value->const_str, strlen((char *) value->const_str), &idx);
            cj_mem_buf_write_u2(buf, idx);
            break;
        }
        case 'e': /*enum*/
        {
            u2 type_name_idx = 0;
            u2 const_name_idx = 0;

            cj_cp_put_str(cls, value->type_name, strlen((char *) value->type_name), &type_name_idx);
            cj_cp_put_str(cls, value->const_name, strlen((char *) value->const_name), &const_name_idx);

            cj_mem_buf_write_u2(buf, type_name_idx);
            cj_mem_buf_write_u2(buf, const_name_idx);
            break;
        }
        case 'c': /*class*/
        {
            cj_mem_buf_write_u2(buf, value->class_info_index);
            break;
        }
        case '@': /*annotation*/
        {
            cj_mem_buf_t *ann_buf = cj_annotation_to_buf(cls, value->annotation);
            cj_mem_buf_write_buf(buf, ann_buf);
            break;
        }
        case '[': /*array*/
        {
            cj_mem_buf_write_u2(buf, value->element_count);

            for (int i = 0; i < value->element_count; ++i) {

                cj_element_t *el = value->elements[i];
                cj_annotation_write_element_value(cls, el, buf);

            }
            break;
        }
        default:
            fprintf(stderr, "ERROR: invalid annotation, unknown element value tag: %c\n", value->tag);
    }

}

cj_mem_buf_t *cj_annotation_to_buf(cj_class_t *cls, cj_annotation_t *ann) {

    if (cls == NULL || ann == NULL) return NULL;

    /*
      annotation {
        u2 type_index;
        u2 num_element_value_pairs;
        {  u2 element_name_index;
           element_value value;
        } element_value_pairs[num_element_value_pairs];
      }
     */
    cj_mem_buf_t *buf = cj_mem_buf_new();

    if (priv(ann)->dirty == 0) {
        buf_ptr start = cj_class_get_buf_ptr(cls, priv(ann)->head);
        cj_mem_buf_write_str(buf, (char *) start, priv(ann)->length); //因为当前长度不包括前六个字节，在此补齐
        cj_mem_buf_flush(buf);
        return buf;
    }

    //currently ann->type_name is a raw type name
    u2 idx = 0;
    cj_cp_put_str(cls, ann->type_name, strlen((char *) ann->type_name), &idx);
    cj_mem_buf_write_u2(buf, idx);

    cj_mem_buf_write_u2(buf, ann->attributes_count);
    if (ann->attributes_count > 0) {
        for (int i = 0; i < ann->attributes_count; ++i) {
            cj_element_pair_t *pair = ann->attributes[i];
            //write name_index
            u2 name_index = 0;
            cj_cp_put_str(cls, pair->name, strlen((char *) pair->name), &name_index);
            cj_mem_buf_write_u2(buf, name_index);
            cj_annotation_write_element_value(cls, pair->value, buf);
        }
    }

    cj_mem_buf_flush(buf);
    return buf;
}

bool cj_annotation_add_kv(cj_annotation_t *ann, const_str key, const_str value) {
    if (ann == NULL || key == NULL) return false;

    cj_element_pair_t *pair = malloc(sizeof(cj_element_pair_t));
    cj_element_t *element = malloc(sizeof(cj_element_t));

    element->tag = 's';
    element->const_str = (const_str) value;
    pair->name = (const_str) key;
    pair->value = element;

    return cj_annotation_add_pair(ann, pair);
}

bool cj_annotation_add_pair(cj_annotation_t *ann, cj_element_pair_t *pair) {
    if (ann == NULL || pair == NULL) return false;

    if (ann->attributes == NULL) {
        ann->attributes = malloc(sizeof(cj_element_pair_t *) * ++ann->attributes_count);
    } else {
        ann->attributes = realloc(ann->attributes, sizeof(cj_element_pair_t *) * ++ann->attributes_count);
    }

    ann->attributes[ann->attributes_count - 1] = pair;

    return true;
}

