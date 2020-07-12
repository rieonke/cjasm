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

struct cj_class_s {
    u2 major_version;
    u2 minor_version;
    u2 access_flags;
    u2 interfaces_count;
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


#endif //CJASM_CJASM_H
