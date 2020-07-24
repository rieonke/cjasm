//
// Created by Rieon Ke on 2020/7/15.
//

#include "util.h"

long cj_load_file(char *path, unsigned char **buf) {

    FILE *f = NULL;
    long len;

    f = fopen(path, "r");
    if (!f) {
        return -1;
    }

    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);

    *buf = malloc(sizeof(char) * (len + 1));
    (*buf)[len] = 0;

    fread(*buf, sizeof(char), len, f);
    fclose(f);

    return len;
}


