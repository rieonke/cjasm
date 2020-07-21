//
// Created by Rieon Ke on 2020/7/16.
//
#include <string.h>
#include <stdio.h>
#include <cjasm.h>
#include "../src/util.h"

#define END printf("}\n");
#define START_CLASS(cls) printf("class %s {\n", cls);

int main(int argc, char **argv) {

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <class-file>\n", argv[0]);
        return 1;
    }

    char *path = argv[1];
    if (path == NULL) {
        fprintf(stderr, "Error: invalid argument[1] :%s\n", path);
        return 1;
    }

    unsigned char *buf = NULL;
    long len = cj_load_file(path, &buf);

    if (len <= 0) {
        fprintf(stderr, "Error: invalid class file size %lu \n", len);
        return 1;
    }

    cj_class_t *cls = cj_class_new(buf, len);
    if (cls == NULL) {
        fprintf(stderr, "Error: failed to parse class file\n");
        return 1;
    }
    free(buf);

    for (int i = 0; i < cj_class_get_annotation_count(cls); ++i) {
        cj_annotation_t *ann = cj_class_get_annotation(cls, i);

        cj_descriptor_t *descriptor = cj_descriptor_parse(ann->type_name, strlen((char*)ann->type_name));
        printf("@%s", descriptor->type);
        if (ann->attributes_count > 0) {
            printf("{ ");
            for (int j = 0; j < ann->attributes_count; ++j) {
                cj_element_pair_t *pair = ann->attributes[j];
                u1 tag = pair->value->tag;
                switch (tag) {
                    case 'B': /*byte*/
                    case 'C': /*char*/
                    case 'I': /*int*/
                    case 'S': /*short*/
                    case 'Z': /*boolean*/
                    case 'F': /*float*/
                    {
                        printf("%s = %llul", pair->name, pair->value->const_num);
                        break;
                    }
                    case 'D': /*double*/
                    case 'J': /*long*/
                    {
                        printf("%s = %llul", pair->name, pair->value->const_num);
                        break;
                    }
                    case 's':/*string*/
                    {
                        printf("%s = %s", pair->name, pair->value->const_str);
                        break;
                    }
                    case 'e': /*enum*/
                    {
                        printf("%s = %s", pair->name, pair->value->const_name);
                        break;
                    }
                    case 'c': /*class*/
                    {
                        printf("%s = %d", pair->name, pair->value->class_info_index);
                        break;
                    }
                    case '@': /*annotation*/
                    {
                        printf("%s = ANNOTATION", pair->name);
                        break;
                    }
                    case '[': /*array*/
                    {
                        printf("%s = ARRAY", pair->name);
                        break;
                    }
                }
                if (j != ann->attributes_count - 1) {
                    printf("; ");
                }

            }
            printf("}");
        }
        printf("\n");

        cj_descriptor_free(descriptor);
    }

    u2 flags = cls->access_flags;
    if ((flags & ACC_PUBLIC) == ACC_PUBLIC) {
        printf("public ");
    }


    const_str name = cj_class_get_name(cls);
    START_CLASS(name)

    for (int i = 0; i < cj_class_get_field_count(cls); ++i) {
        cj_field_t *field = cj_class_get_field(cls, i);

        cj_descriptor_t *desc = cj_descriptor_parse(field->descriptor, strlen((char*) field->descriptor));
        
        printf("\t%s %s;\n", desc->type, field->name);
        cj_descriptor_free(desc);
    }

    printf("\n");
    for (int i = 0; i < cj_class_get_method_count(cls); ++i) {
        cj_method_t *method = cj_class_get_method(cls, i);

        cj_descriptor_t *descriptor = cj_method_get_descriptor(method);
        if (strcmp((char *) method->name, "<init>") == 0) {
            printf("\t%s() {\n", cj_class_get_short_name(cls));
        } else {
            printf("\t%s %s() {\n", descriptor->type, method->name);
        }


        cj_code_t *code = cj_method_get_code(method);
        cj_code_iter_t iter = cj_code_iter_start(code);
        while (cj_code_iter_has_next(&iter)) {
            cj_insn_t *insn = cj_code_iter_next(&iter);
            printf("\t\t");
            cj_print_opcode(insn->opcode);
            cj_insn_free(insn);
        }


        printf("\t}\n\n");
    }

    END


    cj_class_free(cls);
    return 0;
}

