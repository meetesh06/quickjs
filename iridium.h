#ifndef LIBIRID_H
#define LIBIRID_H

#include <stdio.h>
#include <stdbool.h>
#include "./quickjs.h"
#include "./cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum  {
    NUMBER,
    STRING,
    BOOLEAN,
    NULLPTR
} IridiumDataType;

typedef struct IridiumFlag {
    char * name;
    IridiumDataType datatype;
    union {
        double number;
        char * string;
        bool boolean;
        void * null;
    } value;
} IridiumFlag;

typedef struct IridiumSEXP {
    char * tag;
    struct IridiumSEXP ** args;
    int numArgs;
    struct IridiumFlag ** flags;
    int numFlags;
} IridiumSEXP;

IridiumSEXP *parseIridiumSEXP(cJSON *node);

// Given a path to a file, parse and load iridium code
void eval_iri_file(JSContext *ctx, const char *filename);

// Some basic bit operations
void setBit(int bitIndex, int *value);
void clearBit(int bitIndex, int *value);
void toggleBit(int bitIndex, int *value);
bool isBitSet(int bitIndex, int value);

#ifdef __cplusplus
}
#endif

#endif /* LIBIRID_H */
