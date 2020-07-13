//
// Created by Rieon Ke on 2020/7/9.
//

#ifndef CJASM_CJASM_H
#define CJASM_CJASM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef int8_t i1;
typedef int16_t i2;
typedef int32_t i4;
typedef uint8_t u1;
typedef uint16_t u2;
typedef uint32_t u4;
typedef uint64_t u8;

typedef void *cj_pointer;

typedef struct cj_class_s cj_class_t;
typedef struct cj_field_s cj_field_t;
typedef struct cj_method_s cj_method_t;
typedef struct cj_attr_s cj_attr_t;
typedef enum cj_attr_type cj_attr_type_t;


//@formatter:off
/*
+--------------------------------------+----------------------------+------------+---------+
|              Attribute               |          Location          | Class File | Java SE |
+--------------------------------------+----------------------------+------------+---------+
| AnnotationDefault                    | Method                     |         49 |       5 |
| BootstrapMethods                     | Class                      |         51 |       7 |
| Code                                 | Method                     |       45.3 |   1.0.2 |
| ConstantValue                        | Field                      |       45.3 |   1.0.2 |
| Deprecated                           | Class, Method, Field       |       45.3 |     1.1 |
| EnclosingMethod                      | Class                      |         49 |       5 |
| Exceptions                           | Method                     |       45.3 |   1.0.2 |
| InnerClasses                         | Class                      |       45.3 |     1.1 |
| LineNumberTable                      | Code                       |       45.3 |   1.0.2 |
| LocalVariableTable                   | Code                       |       45.3 |   1.0.2 |
| LocalVariableTypeTable               | Code                       |         49 |       5 |
| MethodParameters                     | Method                     |         52 |       8 |
| Module                               | Class                      |         53 |       9 |
| ModuleMainClass                      | Class                      |         53 |       9 |
| ModulePackages                       | Class                      |         53 |       9 |
| NestHost                             | Class                      |         55 |      11 |
| NestMembers                          | Class                      |         55 |      11 |
| RuntimeInvisibleAnnotations          | Class, Method, Field       |         49 |       5 |
| RuntimeInvisibleParameterAnnotations | Method                     |         49 |       5 |
| RuntimeInvisibleTypeAnnotations      | Class, Method, Field, Code |         52 |       8 |
| RuntimeVisibleAnnotations            | Class, Method, Field       |         49 |       5 |
| RuntimeVisibleParameterAnnotations   | Method                     |         49 |       5 |
| RuntimeVisibleTypeAnnotations        | Class, Method, Field, Code |         52 |       8 |
| Signature                            | Class, Method, Field       |         49 |       5 |
| SourceDebugExtension                 | Class                      |         49 |       5 |
| SourceFile                           | Class                      |       45.3 |   1.0.2 |
| StackMapTable                        | Code                       |         50 |       6 |
| Synthetic                            | Class, Method, Field       |       45.3 |     1.1 |
+--------------------------------------+----------------------------+------------+---------+
 */
enum cj_attr_type {
    CJ_ATTR_NONE                                 = 0,
    CJ_ATTR_AnnotationDefault                    = 1,
    CJ_ATTR_BootstrapMethods                     = 2,
    CJ_ATTR_Code                                 = 3,
    CJ_ATTR_ConstantValue                        = 4,
    CJ_ATTR_Deprecated                           = 5,
    CJ_ATTR_EnclosingMethod                      = 6,
    CJ_ATTR_Exceptions                           = 7,
    CJ_ATTR_InnerClasses                         = 8,
    CJ_ATTR_LineNumberTable                      = 9,
    CJ_ATTR_LocalVariableTable                   = 10,
    CJ_ATTR_LocalVariableTypeTable               = 11,
    CJ_ATTR_MethodParameters                     = 12,
    CJ_ATTR_Module                               = 13,
    CJ_ATTR_ModuleMainClass                      = 14,
    CJ_ATTR_ModulePackages                       = 15,
    CJ_ATTR_NestHost                             = 16,
    CJ_ATTR_NestMembers                          = 17,
    CJ_ATTR_RuntimeInvisibleAnnotations          = 18,
    CJ_ATTR_RuntimeInvisibleParameterAnnotations = 19,
    CJ_ATTR_RuntimeInvisibleTypeAnnotations      = 20,
    CJ_ATTR_RuntimeVisibleAnnotations            = 21,
    CJ_ATTR_RuntimeVisibleParameterAnnotations   = 22,
    CJ_ATTR_RuntimeVisibleTypeAnnotations        = 23,
    CJ_ATTR_Signature                            = 24,
    CJ_ATTR_SourceDebugExtension                 = 25,
    CJ_ATTR_SourceFile                           = 26,
    CJ_ATTR_StackMapTable                        = 27,
    CJ_ATTR_Synthetic                            = 28,
};
//@formatter:on


struct cj_class_s {
    u2 major_version;
    u2 minor_version;
    u2 access_flags;
    u2 interface_count;
    u2 attr_count;
    u2 field_count;
    u2 method_count;
    cj_pointer priv;
};

struct cj_field_s {
    u2 access_flags;
    cj_class_t *klass;
    const unsigned char *name;
    const unsigned char *descriptor;
    const char *ptr;
    u2 index;
};

struct cj_method_s {
    u2 access_flags;
    cj_class_t *klass;
    const unsigned char *name;
    const unsigned char *descriptor;
    const char *ptr;
    u2 index;
};

struct cj_attr_s {
    const unsigned char *type_name;
    u4 length;
    cj_attr_type_t type;
};




/**
 * read file content into char buffer.
 * @param path file path
 * @param buf out buffer
 * @return buffer size, error occurred if less than 0
 */
long cj_load_file(char *path, unsigned char **buf);

/**
 * create a cj class context.
 * @param buf bytecode buffer.
 * @param len bytecode length
 * @return context
 */
cj_class_t *cj_class_new(unsigned char *buf, size_t len);

/**
 * 生成字节码.
 * @param ctx cj 类
 * @param out 输出字节码，使用后应被释放，出现错误时，输出为NULL
 * @param len 输出字节码长度，出现错误时，输出为0
 * @return 是否成功
 */
bool cj_class_to_buf(cj_class_t *ctx, unsigned char **out, size_t *len);

/**
 * free a cj class context
 * @param ctx class context
 */
void cj_class_free(cj_class_t *ctx);

/**
 * 跟据索引号从常量池中获取指定的字符串常量.
 * 返回值不可被释放.
 * @param ctx cj 类
 * @param idx 常量池索引，[1 - 常量池长度)
 * @return 字符串，当不存在该索引值或者该常量不是字符串类型时，返回NULL。
 */
const unsigned char *cj_cp_get_str(cj_class_t *ctx, u2 idx);


/**
 * 获取类名.
 * 返回值不可被释放.
 * @param ctx 类
 * @return 类名
 */
const unsigned char *cj_class_get_name(cj_class_t *ctx);

/**
 * 根据索引获取类的字段.
 * 返回值不可被释放.
 * @param ctx cj 类
 * @param idx 字段索引
 * @return 字段，如果不存在该索引值，则返回NULL
 */
cj_field_t *cj_class_get_field(cj_class_t *ctx, u2 idx);

/**
 * 获取类的字段数量.
 * @param ctx 类
 * @return 字段数量，大于或等于0
 */
u2 cj_class_get_field_count(cj_class_t *ctx);

/**
 * 获取类的方法数量
 * @param ctx  类
 * @return 方法数量，大于或等于0
 */
u2 cj_class_get_method_count(cj_class_t *ctx);

/**
 * 根据索引获取类的字段.
 * 返回值不可被释放.
 * @param ctx 类
 * @param idx 方法索引
 * @return 方法，如果不存在该索引值，则返回NULL
 */
cj_method_t *cj_class_get_method(cj_class_t *ctx, u2 idx);

/**
 * 获取类的属性数量.
 * @param ctx 类
 * @return 属性数量，大于或等于0
 */
u2 cj_class_get_attr_count(cj_class_t *ctx);

/**
 * 根据索引获取类的属性.
 * 返回值不可被释放.
 * @param ctx 类
 * @param idx 字段索引
 * @return 字段，如果不存在该索引值，则返回NULL
 */
cj_attr_t *cj_class_get_attr(cj_class_t *ctx, u2 idx);

/**
 * 获取字段名.
 * 返回值不可被释放.
 * @param field cj 字段
 * @return 字段名，不可被释放.
 */
const unsigned char *cj_field_get_name(cj_field_t *field);

/**
 * 设置字段名.
 * @param field  字段.
 * @param name 名称.
 */
void cj_field_set_name(cj_field_t *field, const unsigned char *name);

/**
 * 获取字段Access Flags.
 * @param field cj 字段
 * @return access flags
 */
u2 cj_field_get_access_flags(cj_field_t *field);

/**
 * 获取字段描述符.
 * 返回值不可被释放.
 * @param field 字段
 * @return 字段描述符，不可被释放.
 */
const unsigned char *cj_field_get_descriptor(cj_field_t *field);

const unsigned char *cj_method_get_name(cj_method_t *method);

u2 cj_method_get_access_flags(cj_method_t *method);

const unsigned char *cj_method_get_descriptor(cj_method_t *method);

cj_attr_type_t cj_attr_parse_type(const unsigned char *type_str);

#endif //CJASM_CJASM_H
