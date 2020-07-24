//
// Created by Rieon Ke on 2020/7/23.
//

#include "util.h"
#include "annotation.h"
#include "attribute.h"

CJ_INTERNAL cj_annotation_t *cj_annotation_parse(cj_class_t *ctx, buf_ptr attr_ptr, u4 *out_offset) {

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
    cj_sfree(ann);


}

cj_annotation_t *cj_annotation_group_get(cj_class_t *ctx, cj_annotation_group_t *set, u2 idx) {
    if (set == NULL || set->cache == NULL || idx >= set->count) {
        return NULL;
    }

    return set->cache[idx];
}

CJ_INTERNAL bool cj_annotation_group_init(cj_class_t *ctx, cj_attribute_group_t *attr_set, cj_annotation_group_t **set) {

    cj_annotation_group_t *ann_set = NULL;
    u2 ann_count = 0;
    for (int i = 0; i < attr_set->count; ++i) {
        cj_attribute_t *attr = cj_attribute_group_get(ctx, attr_set, i);
        u4 offset = priva(attr)->offset;

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
            u2 num_annotations = cj_ru2(privc(ctx)->buf + offset + 6);
            offset += 8;

            if (ann_set == NULL) {
                ann_set = malloc(sizeof(cj_annotation_group_t));
                ann_set->count = num_annotations;
                ann_set->index = 0;
                ann_set->offsets = malloc(sizeof(u4) * ann_set->count);
                ann_set->cache = malloc(sizeof(cj_annotation_t *) * ann_set->count);
            } else {
                ann_set->count += num_annotations;
                ann_set->offsets = realloc(ann_set->offsets, sizeof(u4) * ann_set->count);
                ann_set->cache = realloc(ann_set->cache, sizeof(cj_annotation_t *) * ann_set->count);
            }

            for (int j = 0; j < num_annotations; ++j) {
                ann_set->offsets[ann_count] = offset;

                cj_annotation_t *ann = cj_annotation_parse(ctx, privc(ctx)->buf, &offset);
                ann->visible = visible;

                ann_set->cache[ann_count] = ann;
                ++ann_count;
            }
        }
    }

    *set = ann_set;
    return true;
}

