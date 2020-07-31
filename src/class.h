//
// Created by Rieon Ke on 2020/7/23.
//

#ifndef CJASM_CLASS_H
#define CJASM_CLASS_H

#include "def.h"
#include "field.h"
#include "method.h"
#include "cpool.h"
#include "annotation.h"
#include "mem_buf.h"

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

/**
 * 设置类名
 * @param ctx
 * @param name
 */
void cj_class_set_name(cj_class_t *ctx, unsigned char *name);

/**
 * create a cj class context.
 * @param buf bytecode buffer.
 * @param len bytecode length
 * @return context
 */
cj_class_t *cj_class_new(unsigned char *buf, size_t len);

/**
 * free a cj class context
 * @param ctx class context
 */
void cj_class_free(cj_class_t *ctx);

/**
 * 获取类的访问标志
 * 如public/private/protected等
 * @param cls
 * @return
 */
cj_modifiers_t cj_class_get_modifiers(cj_class_t *cls);

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
 * 根据名称获取指定的字段.
 * 返回值不可被释放.
 * @param ctx
 * @param name 字段名
 * @return 字段
 */
cj_field_t *cj_class_get_field_by_name(cj_class_t *ctx, const_str name);

/**
 * 向当前类添加字段.
 * 当字段名已经存在时，返回false
 * @param ctx
 * @param field
 * @return 添加是否成功
 */
bool cj_class_add_field(cj_class_t *ctx, cj_field_t *field);

/**
 * 删除类中的指定字段
 * @param ctx
 * @param idx 字段索引
 * @return 删除是否成功
 */
bool cj_class_remove_field(cj_class_t *ctx, u2 idx);

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
 * 获取注解的集合
 * @param cls
 * @return 注解集合
 */
cj_annotation_group_t *cj_class_get_annotation_group(cj_class_t *cls);


/**
 * 获取当前字节码位置指针.
 * 返回值不可释放
 * @param ctx
 * @param offset 偏移位置
 * @return
 */
buf_ptr cj_class_get_buf_ptr(cj_class_t *ctx, u4 offset);

/**
 * 生成字节码.
 * @param ctx cj 类
 * @param out 输出字节码，使用后应被释放，出现错误时，输出为NULL
 * @param len 输出字节码长度，出现错误时，输出为0
 * @return 是否成功
 */
cj_mem_buf_t *cj_class_to_buf(cj_class_t *ctx);


bool cj_class_write_buf(cj_class_t *cls, cj_mem_buf_t *buf);


cj_cpool_t *cj_class_get_cpool(cj_class_t *ctx);

bool cj_class_add_annotation(cj_class_t *ctx, cj_annotation_t *ann, bool visible);

bool cj_class_remove_method(cj_class_t *ctx, u2 index);

cj_attribute_group_t *cj_class_get_method_attribute_group(cj_class_t *cls, u2 idx);

cj_attribute_group_t *cj_class_get_field_attribute_group(cj_class_t *cls, u2 idx);

CJ_INTERNAL void cj_class_update_name(cj_class_t *ctx, const_str name);

#endif //CJASM_CLASS_H
