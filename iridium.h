#ifndef LIBIRID_H
#define LIBIRID_H

#include <stdio.h>
#include <stdbool.h>
#include "./quickjs.h"
#include "./cJSON.h"
#ifdef __cplusplus
extern "C" {
#endif



// IridiumSEXP *parseIridiumSEXP(cJSON *node);

// Given a path to an iridium file, parse, load and execute
void eval_iri_file(JSContext *ctx, const char *filename);

// Given a path to an iridium pika bundle, parse, load and execute
// void eval_iri_pika(JSContext *ctx, const char *filename);

// Some basic bit operations
void setBit(int bitIndex, int *value);
void clearBit(int bitIndex, int *value);
void toggleBit(int bitIndex, int *value);
bool isBitSet(int bitIndex, int value);

#ifdef __cplusplus
}
#endif

#endif /* LIBIRID_H */
