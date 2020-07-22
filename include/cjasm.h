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
typedef const unsigned char *const_str;
typedef const_str const buf_ptr;

typedef struct cj_class_s cj_class_t;
typedef struct cj_field_s cj_field_t;
typedef struct cj_method_s cj_method_t;
typedef struct cj_attribute_s cj_attribute_t;
typedef struct cj_annotation_s cj_annotation_t;
typedef struct cj_element_pair_s cj_element_pair_t;
typedef struct cj_element_s cj_element_t;
typedef struct cj_code_s cj_code_t;
typedef struct cj_descriptor_s cj_descriptor_t;

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

/**
 *
 *  +------------------+--------+
 *  |    Flag Name     | Value  |
 *  +------------------+--------+
 *  | ACC_PUBLIC       | 0x0001 |
 *  | ACC_PRIVATE      | 0x0002 |
 *  | ACC_PROTECTED    | 0x0004 |
 *  | ACC_STATIC       | 0x0008 |
 *  | ACC_FINAL        | 0x0010 |
 *  | ACC_SYNCHRONIZED | 0x0020 |
 *  | ACC_BRIDGE       | 0x0040 |
 *  | ACC_VARARGS      | 0x0080 |
 *  | ACC_NATIVE       | 0x0100 |
 *  | ACC_ABSTRACT     | 0x0400 |
 *  | ACC_STRICT       | 0x0800 |
 *  | ACC_SYNTHETIC    | 0x1000 |
 *  +------------------+--------+
 */
 enum cj_access_flags {
      ACC_PUBLIC       = 0x0001 ,
      ACC_PRIVATE      = 0x0002 ,
      ACC_PROTECTED    = 0x0004 ,
      ACC_STATIC       = 0x0008 ,
      ACC_FINAL        = 0x0010 ,
      ACC_SYNCHRONIZED = 0x0020 ,
      ACC_BRIDGE       = 0x0040 ,
      ACC_VARARGS      = 0x0080 ,
      ACC_NATIVE       = 0x0100 ,
      ACC_ABSTRACT     = 0x0400 ,
      ACC_STRICT       = 0x0800 ,
      ACC_SYNTHETIC    = 0x1000 ,
 };


enum cj_opcode {
    // Constants
    OP_NOP             = 0x00,
    OP_ACONST_NULL     = 0x01,
    OP_ICONST_M1       = 0x02,
    OP_ICONST_0        = 0x03,
    OP_ICONST_1        = 0x04,
    OP_ICONST_2        = 0x05,
    OP_ICONST_3        = 0x06,
    OP_ICONST_4        = 0x07,
    OP_ICONST_5        = 0x08,
    OP_LCONST_0        = 0x09,
    OP_LCONST_1        = 0x0a,
    OP_FCONST_0        = 0x0b,
    OP_FCONST_1        = 0x0c,
    OP_FCONST_2        = 0x0d,
    OP_DCONST_0        = 0x0e,
    OP_DCONST_1        = 0x0f,
    OP_BIPUSH          = 0x10,
    OP_SIPUSH          = 0x11,
    OP_LDC             = 0x12,
    OP_LDC_W           = 0x13,
    OP_LDC2_W          = 0x14,

    // Loads
    OP_ILOAD           = 0x15,
    OP_LLOAD           = 0x16,
    OP_FLOAD           = 0x17,
    OP_DLOAD           = 0x18,
    OP_ALOAD           = 0x19,
    OP_ILOAD_0         = 0x1a,
    OP_ILOAD_1         = 0x1b,
    OP_ILOAD_2         = 0x1c,
    OP_ILOAD_3         = 0x1d,
    OP_LLOAD_0         = 0x1e,
    OP_LLOAD_1         = 0x1f,
    OP_LLOAD_2         = 0x20,
    OP_LLOAD_3         = 0x21,
    OP_FLOAD_0         = 0x22,
    OP_FLOAD_1         = 0x23,
    OP_FLOAD_2         = 0x24,
    OP_FLOAD_3         = 0x25,
    OP_DLOAD_0         = 0x26,
    OP_DLOAD_1         = 0x27,
    OP_DLOAD_2         = 0x28,
    OP_DLOAD_3         = 0x29,
    OP_ALOAD_0         = 0x2a,
    OP_ALOAD_1         = 0x2b,
    OP_ALOAD_2         = 0x2c,
    OP_ALOAD_3         = 0x2d,
    OP_IALOAD          = 0x2e,
    OP_LALOAD          = 0x2f,
    OP_FALOAD          = 0x30,
    OP_DALOAD          = 0x31,
    OP_AALOAD          = 0x32,
    OP_BALOAD          = 0x33,
    OP_CALOAD          = 0x34,
    OP_SALOAD          = 0x35,

    // Stores
    OP_ISTORE          = 0x36,
    OP_LSTORE          = 0x37,
    OP_FSTORE          = 0x38,
    OP_DSTORE          = 0x39,
    OP_ASTORE          = 0x3a,
    OP_ISTORE_0        = 0x3b,
    OP_ISTORE_1        = 0x3c,
    OP_ISTORE_2        = 0x3d,
    OP_ISTORE_3        = 0x3e,
    OP_LSTORE_0        = 0x3f,
    OP_LSTORE_1        = 0x40,
    OP_LSTORE_2        = 0x41,
    OP_LSTORE_3        = 0x42,
    OP_FSTORE_0        = 0x43,
    OP_FSTORE_1        = 0x44,
    OP_FSTORE_2        = 0x45,
    OP_FSTORE_3        = 0x46,
    OP_DSTORE_0        = 0x47,
    OP_DSTORE_1        = 0x48,
    OP_DSTORE_2        = 0x49,
    OP_DSTORE_3        = 0x4a,
    OP_ASTORE_0        = 0x4b,
    OP_ASTORE_1        = 0x4c,
    OP_ASTORE_2        = 0x4d,
    OP_ASTORE_3        = 0x4e,
    OP_IASTORE         = 0x4f,
    OP_LASTORE         = 0x50,
    OP_FASTORE         = 0x51,
    OP_DASTORE         = 0x52,
    OP_AASTORE         = 0x53,
    OP_BASTORE         = 0x54,
    OP_CASTORE         = 0x55,
    OP_SASTORE         = 0x56,

    // Stack
    OP_POP             = 0x57,
    OP_POP2            = 0x58,
    OP_DUP             = 0x59,
    OP_DUP_X1          = 0x5a,
    OP_DUP_X2          = 0x5b,
    OP_DUP2            = 0x5c,
    OP_DUP2_X1         = 0x5d,
    OP_DUP2_X2         = 0x5e,
    OP_SWAP            = 0x5f,

    // Math
    OP_IADD            = 0x60,
    OP_LADD            = 0x61,
    OP_FADD            = 0x62,
    OP_DADD            = 0x63,
    OP_ISUB            = 0x64,
    OP_LSUB            = 0x65,
    OP_FSUB            = 0x66,
    OP_DSUB            = 0x67,
    OP_IMUL            = 0x68,
    OP_LMUL            = 0x69,
    OP_FMUL            = 0x6a,
    OP_DMUL            = 0x6b,
    OP_IDIV            = 0x6c,
    OP_LDIV            = 0x6d,
    OP_FDIV            = 0x6e,
    OP_DDIV            = 0x6f,
    OP_IREM            = 0x70,
    OP_LREM            = 0x71,
    OP_FREM            = 0x72,
    OP_DREM            = 0x73,
    OP_INEG            = 0x74,
    OP_LNEG            = 0x75,
    OP_FNEG            = 0x76,
    OP_DNEG            = 0x77,
    OP_ISHL            = 0x78,
    OP_LSHL            = 0x79,
    OP_ISHR            = 0x7a,
    OP_LSHR            = 0x7b,
    OP_IUSHR           = 0x7c,
    OP_LUSHR           = 0x7d,
    OP_IAND            = 0x7e,
    OP_LAND            = 0x7f,
    OP_IOR             = 0x80,
    OP_LOR             = 0x81,
    OP_IXOR            = 0x82,
    OP_LXOR            = 0x83,
    OP_IINC            = 0x84,

    // Conversions
    OP_I2L             = 0x85,
    OP_I2F             = 0x86,
    OP_I2D             = 0x87,
    OP_L2I             = 0x88,
    OP_L2F             = 0x89,
    OP_L2D             = 0x8a,
    OP_F2I             = 0x8b,
    OP_F2L             = 0x8c,
    OP_F2D             = 0x8d,
    OP_D2I             = 0x8e,
    OP_D2L             = 0x8f,
    OP_D2F             = 0x90,
    OP_I2B             = 0x91,
    OP_I2C             = 0x92,
    OP_I2S             = 0x93,

    // Comparisons
    OP_LCMP            = 0x94,
    OP_FCMPL           = 0x95,
    OP_FCMPG           = 0x96,
    OP_DCMPL           = 0x97,
    OP_DCMPG           = 0x98,
    OP_IFEQ            = 0x99,
    OP_IFNE            = 0x9a,
    OP_IFLT            = 0x9b,
    OP_IFGE            = 0x9c,
    OP_IFGT            = 0x9d,
    OP_IFLE            = 0x9e,
    OP_IF_ICMPEQ       = 0x9f,
    OP_IF_ICMPNE       = 0xa0,
    OP_IF_ICMPLT       = 0xa1,
    OP_IF_ICMPGE       = 0xa2,
    OP_IF_ICMPGT       = 0xa3,
    OP_IF_ICMPLE       = 0xa4,
    OP_IF_ACMPEQ       = 0xa5,
    OP_IF_ACMPNE       = 0xa6,

    // References
    OP_GETSTATIC       = 0xb2,
    OP_PUTSTATIC       = 0xb3,
    OP_GETFIELD        = 0xb4,
    OP_PUTFIELD        = 0xb5,
    OP_INVOKEVIRTUAL   = 0xb6,
    OP_INVOKESPECIAL   = 0xb7,
    OP_INVOKESTATIC    = 0xb8,
    OP_INVOKEINTERFACE = 0xb9,
    OP_INVOKEDYNAMIC   = 0xba,
    OP_NEW             = 0xbb,
    OP_NEWARRAY        = 0xbc,
    OP_ANEWARRAY       = 0xbd,
    OP_ARRAYLENGTH     = 0xbe,
    OP_ATHROW          = 0xbf,
    OP_CHECKCAST       = 0xc0,
    OP_INSTANCEOF      = 0xc1,
    OP_MONITORENTER    = 0xc2,
    OP_MONITOREXIT     = 0xc3,

    // Control
    OP_GOTO            = 0xa7,
    OP_JSR             = 0xa8,
    OP_RET             = 0xa9,
    OP_TABLESWITCH     = 0xaa,
    OP_LOOKUPSWITCH    = 0xab,
    OP_IRETURN         = 0xac,
    OP_LRETURN         = 0xad,
    OP_FRETURN         = 0xae,
    OP_DRETURN         = 0xaf,
    OP_ARETURN         = 0xb0,
    OP_RETURN          = 0xb1,

    // Extended
    OP_WIDE            = 0xc4,
    OP_MULTIANEWARRAY  = 0xc5,
    OP_IFNULL          = 0xc6,
    OP_IFNONNULL       = 0xc7,
    OP_GOTO_W          = 0xc8,
    OP_JSR_W           = 0xc9,

    // Reserved

    OP_BREAKPOINT      = 0xca,
    OP_IMPDEP1         = 0xfe,
    OP_IMPDEP2         = 0xff

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
    const_str name;
    const_str short_name;
    const_str raw_name;
    const_str package;
    const_str raw_package;
};

struct cj_field_s {
    u2 access_flags;
    cj_class_t *klass;
    const_str name;
    const_str descriptor;
    u2 attribute_count;
    u2 index;
    cj_pointer priv;
};

struct cj_method_s {
    u2 access_flags;
    cj_class_t *klass;
    const_str name;
    const_str descriptor;
    u2 attribute_count;
    u2 index;
    cj_pointer priv;
};

struct cj_attribute_s {
    const_str type_name;
    u4 length;
    enum cj_attr_type type;
    cj_pointer priv;
};

struct cj_annotation_s {
    const_str type_name;
    bool visible;
    u2 attributes_count;
    cj_element_pair_t **attributes;
};

struct cj_descriptor_s {
    bool is_field;
    bool is_method;
    int parameter_count;
    unsigned char **parameter_types;
    unsigned char *type;
};

struct cj_element_pair_s {
    const_str name;
    cj_element_t *value;
};

struct cj_element_s {
    //@formatter:off
    u1 tag;

    /* const value { */
    u8 const_num;
    const_str const_str;
    /* }             */

    /* enum {        */
    const_str type_name;
    const_str const_name;
    /* }             */

    /* class         */
    u2 class_info_index;
    /* }             */

    /* annotation    */
    cj_annotation_t *annotation;
    /* }             */

    /* array         */
    u2 element_count;
    cj_element_t **elements;
    /* }             */
    //@formatter:on
};

struct cj_code_s {
    u4 offset;
    u4 length;
    u2 max_stack;
    u2 max_locals;
    cj_method_t *method;
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
const_str cj_cp_get_str(cj_class_t *ctx, u2 idx);

/**
 * 根据索引号从常量池中获取指定的4字节常量.
 * @param ctx 类
 * @param idx 常量池索引，[1 - 常量池长度)
 * @return 4字节常量
 */
u4 cj_cp_get_u4(cj_class_t *ctx, u2 idx);

/**
 * 根据索引号从常量池中获取指定的int常量
 * @param ctx
 * @param idx
 * @return
 */
int cj_cp_get_int(cj_class_t *ctx, u2 idx);

/**
 * 根据索引号从常量池中获取指定的8字节常量
 * @param ctx 类
 * @param idx 常量池索引，[1 - 常量池长度)
 * @return 8字节常量
 */
u8 cj_cp_get_u8(cj_class_t *ctx, u2 idx);

/**
 * 根据索引号从常量池中获取指定的long常量
 * @param ctx
 * @param idx
 * @return
 */
long cj_cp_get_long(cj_class_t *ctx, u2 idx);

/**
 * 根据索引号从常量池中获取指定的float常量
 * @param ctx
 * @param idx
 * @return
 */
float cj_cp_get_float(cj_class_t *ctx, u2 idx);

/**
 * 根据索引号从常量池中获取指定的double常量
 * @param ctx
 * @param idx
 * @return
 */
double cj_cp_get_double(cj_class_t *ctx, u2 idx);
/**
 * 获取类名.类名格式如 com.example.Test
 * 返回值不可被释放.
 * @param ctx 类
 * @return 类名
 */
const_str cj_class_get_name(cj_class_t *ctx);

/**
 * 获取短名.
 * 如 com.example.Test 短名为 Test.
 * 当没有包名时，短名与类名相同.
 * 返回值不可被释放.
 * @param ctx
 * @return 短名，返回值不可被释放
 */
const_str cj_class_get_short_name(cj_class_t *ctx);


/**
 * 获取原生的类名，如com/example/Test.
 * 返回值不可被释放.
 * @param ctx
 * @return 原生类名
 */
const_str cj_class_get_raw_name(cj_class_t *ctx);

/**
 * 获取包名，如com.example
 * 返回值不可被释放.
 * @param ctx 类
 * @return 包名字符串
 */
const_str cj_class_get_package(cj_class_t *ctx);

/**
 * 获取原生包名，如com/example
 * 返回值不可被释放.
 * @param ctx 类
 * @return 原生包名字符串
 */
const_str cj_class_get_raw_package(cj_class_t *ctx);

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
u2 cj_class_get_attribute_count(cj_class_t *ctx);

/**
 * 根据索引获取类的属性.
 * 返回值不可被释放.
 * @param ctx 类
 * @param idx 属性索引
 * @return 字段，如果不存在该索引值，则返回NULL
 */
cj_attribute_t *cj_class_get_attribute(cj_class_t *ctx, u2 idx);


/**
 * 获取类的注解数量.
 * @param ctx 类
 * @return 注解数量
 */
u2 cj_class_get_annotation_count(cj_class_t *ctx);

/**
 * 根据索引获取指定的注解.
 * 返回值不可释放.
 * @param ctx 类
 * @param idx 注解索引
 * @return 注解，如果不存在该索引值，则返回NULL
 */
cj_annotation_t *cj_class_get_annotation(cj_class_t *ctx, u2 idx);

/**
 * 获取字段名.
 * 返回值不可被释放.
 * @param field cj 字段
 * @return 字段名，不可被释放.
 */
const_str cj_field_get_name(cj_field_t *field);

/**
 * 设置字段名.
 * @param field  字段.
 * @param name 名称.
 */
void cj_field_set_name(cj_field_t *field, const_str name);

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
const_str cj_field_get_descriptor(cj_field_t *field);


/**
 * 获取字段的属性数量.
 * @param field 字段
 * @return 字段数量
 */
u2 cj_field_get_attribute_count(cj_field_t *field);

/**
 * 根据索引值获取字段的属性.
 * 返回值不可被释放.
 * @param field 字段
 * @param idx 索引值
 * @return 属性，当不存在该索引值时，返回NULL
 */
cj_attribute_t *cj_field_get_attribute(cj_field_t *field, u2 idx);

/**
 * 获取字段的注解数量.
 * @param field 字段
 * @return 注解数量
 */
u2 cj_field_get_annotation_count(cj_field_t *field);

/**
 * 根据索引值获取字段的注解.
 * 返回值不可被释放.
 * @param field 字段
 * @param idx 索引
 * @return 注解，当不存在该索引时，返回NULL
 */
cj_annotation_t *cj_field_get_annotation(cj_field_t *field, u2 idx);

/**
 * 获取方法名.
 * 返回值不可被释放.
 * @param method 方法
 * @return 方法名
 */
const_str cj_method_get_name(cj_method_t *method);

/**
 * 获取方法的access_flags.
 * @param method 方法
 * @return access flags
 */
u2 cj_method_get_access_flags(cj_method_t *method);

/**
 * 获取方法的属性数量.
 * @param method 方法
 * @return 属性数量
 */
u2 cj_method_get_attribute_count(cj_method_t *method);

/**
 * 根据索引值获取方法的属性.
 * 返回值不可被释放.
 * @param method 方法
 * @param idx 索引
 * @return 属性，如果不存在该索引值时，返回NULL.
 */
cj_attribute_t *cj_method_get_attribute(cj_method_t *method, u2 idx);


/**
 * 获取方法的注解数量.
 * @param method 方法
 * @return 注解数量
 */
u2 cj_method_get_annotation_count(cj_method_t *method);

/**
 * 根据索引值获取方法的注解.
 * 返回值不可被释放.
 * @param method 方法
 * @param idx 索引
 * @return 属性，如果不存在该索引值时，返回NULL.
 */
cj_annotation_t *cj_method_get_annotation(cj_method_t *method, u2 idx);


/**
 * 获取方法的代码.
 * 返回值不可被释放.
 * @param method 方法
 * @return 代码，如果不存在代码时，返回NULL
 */
cj_code_t *cj_method_get_code(cj_method_t *method);


/**
 * 获取方法参数数量.
 * @param method 方法
 * @return 方法数量
 */
u2 cj_method_get_parameter_count(cj_method_t *method);


/**
 * 获取方法返回值类型.
 * 返回值不可被释放.
 * @param method 方法
 * @return 返回值类型
 */
const_str cj_method_get_return_type(cj_method_t *method);


/**
 * 获取方法描述符.
 * 返回值不可被释放.
 * @param method 方法
 * @return 方法描述符
 */
cj_descriptor_t *cj_method_get_descriptor(cj_method_t *method);


/**
 * 根据属性名解析属性类型.
 * @param type_str 属性名
 * @return 属性类型
 */
enum cj_attr_type cj_attr_parse_type(const_str type_str);

#endif //CJASM_CJASM_H
