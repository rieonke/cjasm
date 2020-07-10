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

typedef struct cj_class_s cj_class_t;
struct cj_class_s {
    u2 major_version;
    u2 minor_version;
    u2 cp_len;
    u2 *cp_offsets;
    u4 header;
    u2 access_flags;
    unsigned char const *buf;
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
 * free a cj class context
 * @param ctx class context
 */
void cj_class_free(cj_class_t *ctx);

/**
 * get a string from constant pool.
 * @param cls cj class context
 * @return string, should be freed by yourself
 */
int cj_cp_get_str(cj_class_t *ctx, u2 idx, unsigned char **out);

#endif //CJASM_CJASM_H
