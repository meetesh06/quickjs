#include "./iridium.h"
#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"
#include "./quickjs_expose.h"
#include "./quickjs-opcode.h"
#include "./cutils.h"
#include <assert.h>
#include <ctype.h>

#define check_dump_flag(ctx, flag)  ((JS_GetDumpFlags(ctx->rt) & (flag +0)) == (flag +0))

#define OP_DEFINE_METHOD_METHOD 0
#define OP_DEFINE_METHOD_GETTER 1
#define OP_DEFINE_METHOD_SETTER 2
#define OP_DEFINE_METHOD_ENUMERABLE 4

#define JS_STACK_SIZE_MAX 65534

typedef enum OPCodeFormat
{
#define FMT(f) OP_FMT_##f,
#define DEF(id, size, n_pop, n_push, f)
#include "quickjs-opcode.h"
#undef DEF
#undef FMT
} OPCodeFormat;

typedef enum
{
  /* XXX: add more variable kinds here instead of using bit fields */
  JS_VAR_NORMAL,
  JS_VAR_FUNCTION_DECL,     /* lexical var with function declaration */
  JS_VAR_NEW_FUNCTION_DECL, /* lexical var with async/generator
                               function declaration */
  JS_VAR_CATCH,
  JS_VAR_FUNCTION_NAME, /* function expression name */
  JS_VAR_PRIVATE_FIELD,
  JS_VAR_PRIVATE_METHOD,
  JS_VAR_PRIVATE_GETTER,
  JS_VAR_PRIVATE_SETTER,        /* must come after JS_VAR_PRIVATE_GETTER */
  JS_VAR_PRIVATE_GETTER_SETTER, /* must come after JS_VAR_PRIVATE_SETTER */
} JSVarKindEnum;

typedef enum OPCodeEnum
{
#define FMT(f)
#define DEF(id, size, n_pop, n_push, f) OP_##id,
#define def(id, size, n_pop, n_push, f)
#include "quickjs-opcode.h"
#undef def
#undef DEF
#undef FMT
  OP_COUNT, /* excluding temporary opcodes */
  /* temporary opcodes : overlap with the short opcodes */
  OP_TEMP_START = OP_nop + 1,
  OP___dummy = OP_TEMP_START - 1,
#define FMT(f)
#define DEF(id, size, n_pop, n_push, f)
#define def(id, size, n_pop, n_push, f) OP_##id,
#include "quickjs-opcode.h"
#undef def
#undef DEF
#undef FMT
  OP_TEMP_END,
} OPCodeEnum;

#define ENABLE_DUMPS

typedef struct JSOpCode
{
#ifdef ENABLE_DUMPS // JS_DUMP_BYTECODE_*
  const char *name;
#endif
  uint8_t size; /* in bytes */
  /* the opcodes remove n_pop items from the top of the stack, then
     pushes n_push items */
  uint8_t n_pop;
  uint8_t n_push;
  uint8_t fmt;
} JSOpCode;

static const JSOpCode opcode_info[OP_COUNT + (OP_TEMP_END - OP_TEMP_START)] = {
#define FMT(f)
#ifdef ENABLE_DUMPS // JS_DUMP_BYTECODE_*
#define DEF(id, size, n_pop, n_push, f) {#id, size, n_pop, n_push, OP_FMT_##f},
#else
#define DEF(id, size, n_pop, n_push, f) {size, n_pop, n_push, OP_FMT_##f},
#endif
#include "quickjs-opcode.h"
#undef DEF
#undef FMT
};

#define short_opcode_info(op) \
   opcode_info[(op) >= OP_TEMP_START ? (op) + (OP_TEMP_END - OP_TEMP_START) : (op)]

//
// Reading and loading source JSON data
//
char *read_file(const char *filename)
{
  FILE *file = fopen(filename, "rb");
  if (file == NULL)
  {
    perror("File opening failed");
    return NULL;
  }

  fseek(file, 0, SEEK_END);
  long length = ftell(file);
  rewind(file);

  char *data = (char *)malloc(length + 1);
  if (data == NULL)
  {
    fclose(file);
    return NULL;
  }

  fread(data, 1, length, file);
  data[length] = '\0'; // Null-terminate

  fclose(file);
  return data;
}

cJSON *load_json(const char *path)
{
  char *json_data = read_file(path);
  if (json_data == NULL)
  {
    return NULL;
  }

  cJSON *json = cJSON_Parse(json_data);
  free(json_data); // free the buffer after parsing
  return json;
}

//
// Parsing and creating Iridium S-Expression Tree
//
void populateArgs(IridiumSEXP *res, cJSON *args)
{
  int argsNum = res->numArgs = cJSON_GetArraySize(args);
  res->args = malloc(argsNum * sizeof(IridiumSEXP **));
  for (int i = 0; i < argsNum; ++i)
  {
    res->args[i] = parseIridiumSEXP(cJSON_GetArrayItem(args, i));
  }
}

void populateFlags(IridiumSEXP *res, cJSON *flags)
{
  int flagsNum = res->numFlags = cJSON_GetArraySize(flags);
  res->flags = malloc(flagsNum * sizeof(IridiumSEXP **));
  for (int i = 0; i < flagsNum; ++i)
  {
    cJSON *flag = cJSON_GetArrayItem(flags, i);
    if (cJSON_GetArraySize(flag) != 2)
    {
      fprintf(stderr, "Expected flag array size to be 2\n");
      exit(1);
    }

    char *flagName = cJSON_GetStringValue(cJSON_GetArrayItem(flag, 0));
    cJSON *flagVal = cJSON_GetArrayItem(flag, 1);

    IridiumFlag *currFlag = malloc(sizeof(IridiumFlag));
    res->flags[i] = currFlag;
    currFlag->name = flagName;

    // Handle Iridium Primitives
    if (cJSON_IsBool(flagVal))
    {
      currFlag->value.boolean = cJSON_IsTrue(flagVal) ? true : false;
      currFlag->datatype = BOOLEAN;
    }
    else if (cJSON_IsNumber(flagVal))
    {
      currFlag->value.number = cJSON_GetNumberValue(flagVal);
      currFlag->datatype = NUMBER;
    }
    else if (cJSON_IsString(flagVal))
    {
      currFlag->value.string = cJSON_GetStringValue(flagVal);
      currFlag->datatype = STRING;
    }
    else
    {
      currFlag->value.null = NULL;
      currFlag->datatype = NULLPTR;
    }
  }
}

IridiumSEXP *parseNode(char *tag, cJSON *args, cJSON *flags)
{
  IridiumSEXP *res = malloc(sizeof(IridiumSEXP));
  res->tag = tag;
  populateArgs(res, args);
  populateFlags(res, flags);
  return res;
}

IridiumSEXP *parseIridiumSEXP(cJSON *node)
{
  if (cJSON_IsArray(node))
  {
    cJSON *tagPtr = node->child;
    char *tag;
    if (!cJSON_IsString(tagPtr))
    {
      fprintf(stderr, "Iridium parsing failed, expected tag to be a string\n");
      exit(1);
    }
    tag = cJSON_GetStringValue(tagPtr);

    cJSON *args = node->child->next;
    cJSON *flags = node->child->next->next;

    // Pre-Assertions
    if (!cJSON_IsArray(args))
    {
      fprintf(stderr, "Expected args to be an array");
      exit(1);
    }

    if (!cJSON_IsArray(flags))
    {
      fprintf(stderr, "Expected flags to be an array");
      exit(1);
    }

    // parse node
    return parseNode(tag, args, flags);

    fprintf(stdout, "%s", tag);
  }
  else
  {
    fprintf(stderr, "Iridium parsing failed, expected an array");
    exit(1);
  }

  return NULL;
}

//
// Printing Iridium S-Expression Tree
//
void printSpace(FILE *target, int space)
{
  while (space-- > 0)
    fprintf(target, " ");
}

void dumpFlag(FILE *target, IridiumFlag *flag)
{
  if (flag->datatype == NUMBER)
  {
    fprintf(target, "%s => %f", flag->name, flag->value.number);
  }
  else if (flag->datatype == STRING)
  {
    fprintf(target, "%s => %s", flag->name, flag->value.string);
  }
  else if (flag->datatype == BOOLEAN)
  {
    fprintf(target, "%s => %s", flag->name, flag->value.boolean ? "TRUE" : "FALSE");
  }
  else
  {
    fprintf(target, "%s", flag->name);
  }
}

void dumpIridiumSEXP(FILE *target, IridiumSEXP *node, int space)
{
  printSpace(target, space);
  fprintf(target, "%s(", node->tag);
  IridiumFlag **flags = node->flags;

  for (int i = 0; i < node->numFlags; ++i)
  {
    IridiumFlag *currFlag = flags[i];
    dumpFlag(target, currFlag);
    if (i + 1 != node->numFlags)
      fprintf(target, ", ");
  }

  fprintf(target, ")\n");

  IridiumSEXP **args = node->args;
  for (int i = 0; i < node->numArgs; ++i)
  {
    IridiumSEXP *currArg = args[i];
    dumpIridiumSEXP(target, currArg, space + 2);
  }
}

//
// Generate Bytecode
//
typedef struct BCLList
{
  struct BCLList *next;
  uint8_t bc;
  bool lambdaPoolReference;
  bool hasPoolData;
  JSValue poolData;
  bool isLabel;
  int label;
  union
  {
    uint8_t one;
    uint16_t two;
    uint32_t four;
  } data;
  uint8_t valueSize;
  bool hasFlags;
  uint8_t flags;
  // Extend the data structure to accomodate arguments dynamically
} BCLList;

// ============== Push OP ============== //
BCLList *pushLabel(JSContext *ctx, BCLList *currTarget, int label)
{
  currTarget->next = malloc(sizeof(BCLList));
  currTarget = currTarget->next;
  currTarget->next = NULL;
  currTarget->bc = OP_nop;
  currTarget->lambdaPoolReference = false;
  currTarget->hasPoolData = false;
  currTarget->poolData = JS_UNINITIALIZED;
  currTarget->isLabel = true;
  currTarget->label = label;
  currTarget->valueSize = 0;
  currTarget->data.four = 0;
  currTarget->hasFlags = false;
  currTarget->flags = 0;
  return currTarget;
}

// BCLList *push8(JSContext *ctx, BCLList *currTarget, uint8_t opcode)
// {
//   currTarget->next = malloc(sizeof(BCLList));
//   currTarget = currTarget->next;
//   currTarget->next = NULL;
//   currTarget->bc = opcode;
//   currTarget->lambdaPoolReference = false;
//   currTarget->hasPoolData = false;
//   currTarget->poolData = JS_UNINITIALIZED;
//   currTarget->isLabel = false;
//   currTarget->label = 0;
//   currTarget->valueSize = 0;
//   currTarget->data.four = 0;
//   return currTarget;
// }

BCLList *pushOP(JSContext *ctx, BCLList *currTarget, OPCodeEnum opcode)
{
  currTarget->next = malloc(sizeof(BCLList));
  currTarget = currTarget->next;
  currTarget->next = NULL;
  currTarget->bc = opcode;
  currTarget->lambdaPoolReference = false;
  currTarget->hasPoolData = false;
  currTarget->poolData = JS_UNINITIALIZED;
  currTarget->isLabel = false;
  currTarget->label = 0;
  currTarget->valueSize = 0;
  currTarget->data.four = 0;
  currTarget->hasFlags = false;
  currTarget->flags = 0;
  return currTarget;
}

BCLList *pushOPFlags(JSContext *ctx, BCLList *currTarget, OPCodeEnum opcode, uint8_t flags)
{
  currTarget->next = malloc(sizeof(BCLList));
  currTarget = currTarget->next;
  currTarget->next = NULL;
  currTarget->bc = opcode;
  currTarget->lambdaPoolReference = false;
  currTarget->hasPoolData = false;
  currTarget->poolData = JS_UNINITIALIZED;
  currTarget->isLabel = false;
  currTarget->label = 0;
  currTarget->valueSize = 0;
  currTarget->data.four = 0;
  currTarget->hasFlags = true;
  currTarget->flags = flags;
  return currTarget;
}

BCLList *pushOP8(JSContext *ctx, BCLList *currTarget, OPCodeEnum opcode, uint8_t data)
{
  currTarget->next = malloc(sizeof(BCLList));
  currTarget = currTarget->next;
  currTarget->next = NULL;
  currTarget->bc = opcode;
  currTarget->lambdaPoolReference = false;
  currTarget->hasPoolData = false;
  currTarget->poolData = JS_UNINITIALIZED;
  currTarget->isLabel = false;
  currTarget->label = 0;
  currTarget->valueSize = 1;
  currTarget->data.one = data;
  currTarget->hasFlags = false;
  currTarget->flags = 0;
  return currTarget;
}

BCLList *pushOP16(JSContext *ctx, BCLList *currTarget, OPCodeEnum opcode, uint16_t data)
{
  currTarget->next = malloc(sizeof(BCLList));
  currTarget = currTarget->next;
  currTarget->next = NULL;
  currTarget->bc = opcode;
  currTarget->lambdaPoolReference = false;
  currTarget->hasPoolData = false;
  currTarget->poolData = JS_UNINITIALIZED;
  currTarget->isLabel = false;
  currTarget->label = 0;
  currTarget->valueSize = 2;
  currTarget->data.two = data;
  currTarget->hasFlags = false;
  currTarget->flags = 0;
  return currTarget;
}

BCLList *pushOP32(JSContext *ctx, BCLList *currTarget, OPCodeEnum opcode, uint32_t data)
{
  currTarget->next = malloc(sizeof(BCLList));
  currTarget = currTarget->next;
  currTarget->next = NULL;
  currTarget->bc = opcode;
  currTarget->lambdaPoolReference = false;
  currTarget->hasPoolData = false;
  currTarget->poolData = JS_UNINITIALIZED;
  currTarget->isLabel = false;
  currTarget->label = 0;
  currTarget->valueSize = 4;
  currTarget->data.four = data;
  currTarget->hasFlags = false;
  currTarget->flags = 0;
  return currTarget;
}

BCLList *pushOP32Flags(JSContext *ctx, BCLList *currTarget, OPCodeEnum opcode, uint32_t data, uint8_t flags)
{
  currTarget->next = malloc(sizeof(BCLList));
  currTarget = currTarget->next;
  currTarget->next = NULL;
  currTarget->bc = opcode;
  currTarget->lambdaPoolReference = false;
  currTarget->hasPoolData = false;
  currTarget->poolData = JS_UNINITIALIZED;
  currTarget->isLabel = false;
  currTarget->label = 0;
  currTarget->valueSize = 4;
  currTarget->data.four = data;
  currTarget->hasFlags = true;
  currTarget->flags = flags;
  return currTarget;
}

BCLList *pushOPConst(JSContext *ctx, BCLList *currTarget, OPCodeEnum opcode, JSValue cData)
{
  currTarget->next = malloc(sizeof(BCLList));
  currTarget = currTarget->next;
  currTarget->next = NULL;
  currTarget->bc = opcode;
  currTarget->lambdaPoolReference = false;
  currTarget->hasPoolData = true;
  currTarget->poolData = cData;
  currTarget->isLabel = false;
  currTarget->label = 0;
  currTarget->valueSize = 4;
  currTarget->data.four = 0;
  currTarget->hasFlags = false;
  currTarget->flags = 0;
  return currTarget;
}

// ============== Push OP ============== //

// ============== Flag Related ============== //

bool isTag(IridiumSEXP *node, const char *const tag)
{
  return strcmp(node->tag, tag) == 0;
}

void ensureTag(IridiumSEXP *node, const char *const tag)
{
  if (!isTag(node, tag))
  {
    fprintf(stderr, "Expected tag %s, found %s\n", tag, node->tag);
    exit(1);
  }
}

bool hasFlag(IridiumSEXP *node, char *flagToCheck)
{
  for (int i = 0; i < node->numFlags; i++)
  {
    IridiumFlag *flag = node->flags[i];
    if (strcmp(flag->name, flagToCheck) == 0)
      return true;
  }
  return false;
}

void ensureFlag(IridiumSEXP *node, char *flag)
{
  if (!hasFlag(node, flag))
  {
    fprintf(stderr, "Expected flag %s not found\n", flag);
    exit(1);
  }
}

IridiumFlag *getFlag(IridiumSEXP *node, const char *const flagToCheck)
{
  for (int i = 0; i < node->numFlags; i++)
  {
    IridiumFlag *flag = node->flags[i];
    if (strcmp(flag->name, flagToCheck) == 0)
      return flag;
  }
  fprintf(stderr, "Failed to get flag, %s not found\n", flagToCheck);
  exit(1);
}

int getFlagNumber(IridiumSEXP *binding, char *flagName)
{
  IridiumFlag *flag = getFlag(binding, flagName);
  if (flag->datatype == NUMBER)
  {
    return flag->value.number;
  }
  fprintf(stderr, "TODO: failed to get NUMBER\n");
  exit(1);
}

double getFlagDouble(IridiumSEXP *binding, char *flagName)
{
  IridiumFlag *flag = getFlag(binding, flagName);
  if (flag->datatype == NUMBER)
  {
    return flag->value.number;
  }
  fprintf(stderr, "TODO: failed to get NUMBER(double)\n");
  exit(1);
}


char *getFlagString(IridiumSEXP *binding, char *flagName)
{
  IridiumFlag *flag = getFlag(binding, flagName);
  if (flag->datatype == STRING)
  {
    return flag->value.string;
  }
  fprintf(stderr, "TODO: failed to get STRING\n");
  exit(1);
}

bool getFlagBoolean(IridiumSEXP *binding, char *flagName)
{
  IridiumFlag *flag = getFlag(binding, flagName);
  if (flag->datatype == BOOLEAN)
  {
    return flag->value.boolean;
  }
  fprintf(stderr, "TODO: failed to get BOOLEAN\n");
  exit(1);
}

int getFlagNull(IridiumSEXP *binding, char *flagName)
{
  IridiumFlag *flag = getFlag(binding, flagName);
  if (flag->datatype == NULLPTR)
  {
    return 0;
  }
  fprintf(stderr, "TODO: failed to get NULLPTR\n");
  exit(1);
}
// ============== Flag Related ============== //

// ============== Code Generation ============== //

BCLList *handleEnvWrite(JSContext *ctx, BCLList *currTarget, IridiumSEXP *currStmt, bool saveResToStack);

int parse_arg_index(const char *str)
{
  const char *prefix = "ARG";
  size_t prefix_len = strlen(prefix);

  if (strncmp(str, prefix, prefix_len) != 0)
    return -1;

  // Ensure remaining characters are digits
  const char *number_part = str + prefix_len;
  for (const char *p = number_part; *p != '\0'; ++p)
  {
    if (!isdigit((unsigned char)*p))
      return -1;
  }

  return atoi(number_part);
}

// ============== Misc ============== //

BCLList *storeWhatevesOnTheStack(JSContext* ctx, IridiumSEXP *loc, BCLList * currTarget, bool safe, bool thisInit, bool isStrict, bool saveResToStack) {  
  if (saveResToStack)
    currTarget = pushOP(ctx, currTarget, OP_dup);

  // is lval global?
  if (isTag(loc, "GlobalBinding"))
  {
    char *name = getFlagString(loc, "NAME");

    if (safe)
    {
      currTarget = pushOP32(ctx, currTarget, OP_put_var_init, JS_NewAtom(ctx, name));
    }
    else if (isStrict)
    {
      currTarget = pushOP32(ctx, currTarget, OP_check_var, JS_NewAtom(ctx, name));
      currTarget = pushOP(ctx, currTarget, OP_swap);
      currTarget = pushOP32(ctx, currTarget, OP_put_var_strict, JS_NewAtom(ctx, name));
    }
    else
    {
      currTarget = pushOP32(ctx, currTarget, OP_put_var, JS_NewAtom(ctx, name));
    }
  }
  else
  {
    if (thisInit)
    {
      // This init only happens for locals...
      assert(isTag(loc, "EnvBinding"));
      int refIdx = getFlagNumber(loc, "REFIDX");
      currTarget = pushOP16(ctx, currTarget, OP_put_loc_check_init, refIdx);
    }
    else if (isTag(loc, "RemoteEnvBinding"))
    {
      int refIdx = getFlagNumber(loc, "REFIDX");
      currTarget = pushOP16(ctx, currTarget, safe ? OP_put_var_ref : OP_put_var_ref_check, refIdx);
    }
    else if (isTag(loc, "EnvBinding"))
    {
      int refIdx = getFlagNumber(loc, "REFIDX");
      currTarget = pushOP16(ctx, currTarget, safe ? OP_put_loc : OP_put_loc_check, refIdx);
    }
    else
    {
      fprintf(stderr, "TODO: store on stack, unhandled loc kind!!");
      exit(1);
    }
  }

  return currTarget;
}


// ============== Misc ============== //


BCLList *lowerToStack(JSContext *ctx, BCLList *currTarget, IridiumSEXP *rval)
{
  if (isTag(rval, "String"))
  {
    char *data = getFlagString(rval, "IridiumPrimitive");
    JSAtom strAtom = JS_NewAtom(ctx, data);
    return pushOP32(ctx, currTarget, OP_push_atom_value, strAtom);
  }
  else if (isTag(rval, "RegExp"))
  {
    char *exp = getFlagString(rval, "EXP");
    char *flags = getFlagString(rval, "FLAGS");

    JSValue expValue = JS_NewAtomString(ctx, exp);
    JSValue flagsValue = JS_NewAtomString(ctx, flags);

    currTarget = pushOPConst(ctx, currTarget, OP_push_const, expValue);

    // Compile regexp
    if (!ctx->compile_regexp)
    {
      fprintf(stderr, "RegExp compiler not found in the context");
      exit(1);
    }
    JSValue compiledRegexp = ctx->compile_regexp(ctx, expValue, flagsValue);
    currTarget = pushOPConst(ctx, currTarget, OP_push_const, compiledRegexp);
    return pushOP(ctx, currTarget, OP_regexp);
  }
  else if (isTag(rval, "JSTemplate"))
  {
    currTarget = pushOP(ctx, currTarget, OP_push_empty_string);
    JSAtom fieldAtom = JS_NewAtom(ctx, "concat");
    currTarget = pushOP32(ctx, currTarget, OP_get_field2, fieldAtom);

    for (int i = 0; i < rval->numArgs; i++)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[i]);
    }

    return pushOP16(ctx, currTarget, OP_call_method, rval->numArgs);
  }
  else if (isTag(rval, "Number"))
  {
    double data = getFlagDouble(rval, "IridiumPrimitive");
    JSValue jsvalue = JS_NewNumber(ctx, data);
    return pushOPConst(ctx, currTarget, OP_push_const, jsvalue);
  }
  else if (isTag(rval, "JSNUBD"))
  {
    return pushOPConst(ctx, currTarget, OP_push_const, JS_UNINITIALIZED);
  }
  else if (isTag(rval, "RemoteEnvBinding"))
  {
    int refIDX = getFlagNumber(rval, "REFIDX");
    return pushOP16(ctx, currTarget, OP_get_var_ref_check, refIDX);
  }
  else if (isTag(rval, "EnvBinding"))
  {
    // If this is an arg, get the arg idx
    if (hasFlag(rval, "JSARG"))
    {
      int argIdx = getFlagNumber(rval, "REFIDX");
      // int argIdx = parse_arg_index(getFlagString(rval->args[0], "IridiumPrimitive"));
      assert(argIdx > -1);
      return pushOP16(ctx, currTarget, OP_get_arg, argIdx);
    }
    else if (hasFlag(rval, "JSRESTARG"))
    {
      int argIdx = getFlagNumber(rval, "REFIDX");
      // int argIdx = parse_arg_index(getFlagString(rval->args[0], "IridiumPrimitive"));
      assert(argIdx > -1);
      return pushOP16(ctx, currTarget, OP_rest, argIdx);
    }
    else
    {
      int refIDX = getFlagNumber(rval, "REFIDX");
      return pushOP16(ctx, currTarget, OP_get_loc_check, refIDX);
    }
  }
  else if (isTag(rval, "GlobalBinding"))
  {
    char *lookupVal = getFlagString(rval, "NAME");
    if (strcmp(lookupVal, "undefined") == 0)
      return pushOP(ctx, currTarget, OP_undefined);
    else
      return pushOP32(ctx, currTarget, OP_get_var, JS_NewAtom(ctx, lookupVal));
  }
  else if (isTag(rval, "CallSite"))
  {
    int i = 0;

    // Handle Constructor Call Context, the class object is duplicated on the stack
    if (hasFlag(rval, "ConstructorCall"))
    {
      assert(rval->numArgs >= 1);
      currTarget = lowerToStack(ctx, currTarget, rval->args[0]);
      currTarget = pushOP(ctx, currTarget, OP_dup);
      i = 1;
    }

    // Private Call needs to be behind a brand check
    if (hasFlag(rval, "PrivateCall"))
    {
      assert(rval->numArgs >= 2);
      currTarget = lowerToStack(ctx, currTarget, rval->args[0]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = pushOP(ctx, currTarget, OP_check_brand); // Ensure the function's home object's brand matches the brand of the current instance current instance.
      i = 2;
    }

    // Lower Arguments
    for (; i < rval->numArgs; i++)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[i]);
    }

    // Emit Call
    if (hasFlag(rval, "Super"))
    {
      return pushOP16(ctx, currTarget, OP_call_constructor, rval->numArgs - 2);
    }
    else if (hasFlag(rval, "ConstructorCall"))
    {
      return pushOP16(ctx, currTarget, OP_call_constructor, rval->numArgs - 1);
    }
    else if (hasFlag(rval, "CCall"))
    {
      return pushOP16(ctx, currTarget, OP_call_method, rval->numArgs - 2);
    }
    else if (hasFlag(rval, "PrivateCall"))
    {
      return pushOP16(ctx, currTarget, OP_call_method, rval->numArgs - 2);
    }
    else
    {
      return pushOP16(ctx, currTarget, OP_call, rval->numArgs - 1);
    }
  }
  else if (isTag(rval, "EnvRead"))
  {
    return lowerToStack(ctx, currTarget, rval->args[0]);
  }
  else if (isTag(rval, "EnvWrite"))
  {
    return handleEnvWrite(ctx, currTarget, rval, true);
  }
  else if (isTag(rval, "Boolean"))
  {
    bool res = getFlagBoolean(rval, "IridiumPrimitive");
    if (res)
    {
      return pushOP(ctx, currTarget, OP_push_true);
    }
    else
    {
      return pushOP(ctx, currTarget, OP_push_false);
    }
  }
  else if (isTag(rval, "Unop"))
  {
    char *op = getFlagString(rval->args[0], "IridiumPrimitive");
    if (strcmp(op, "!") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      return pushOP(ctx, currTarget, OP_lnot);
    }
    else if (strcmp(op, "-") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      return pushOP(ctx, currTarget, OP_neg);
    }
    else if (strcmp(op, "+") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      return pushOP(ctx, currTarget, OP_plus);
    }
    else if (strcmp(op, "~") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      return pushOP(ctx, currTarget, OP_not);
    }
    else if (strcmp(op, "typeof") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      return pushOP(ctx, currTarget, OP_typeof);
    }
    else if (strcmp(op, "delete") == 0)
    {
      IridiumSEXP *valToDelete = rval->args[1];
      assert(isTag(valToDelete, "List"));
      if (hasFlag(valToDelete, "UNOP_DEL_MEMBEREXPR"))
      {
        IridiumSEXP *receiver = valToDelete->args[0];
        IridiumSEXP *field = valToDelete->args[1];
        currTarget = lowerToStack(ctx, currTarget, receiver);
        currTarget = lowerToStack(ctx, currTarget, field);
        return pushOP(ctx, currTarget, OP_delete);
      }
      else if (hasFlag(valToDelete, "UNOP_DEL_VAR"))
      {
        IridiumSEXP *var = valToDelete->args[0];
        assert(isTag(var, "String"));
        JSAtom varAtom = JS_NewAtom(ctx, getFlagString(var, "IridiumPrimitive"));
        return pushOP32(ctx, currTarget, OP_delete_var, varAtom);
      }
      else
      {
        fprintf(stderr, "TODO: Unhandled : %s\n", op);
        exit(1);
      }
    }
    else
    {
      fprintf(stderr, "TODO: unhandled Unop: %s\n", op);
      exit(1);
    }
  }
  else if (isTag(rval, "Binop"))
  {
    char *op = getFlagString(rval->args[0], "IridiumPrimitive");
    if (strcmp(op, "+") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_add);
    }
    else if (strcmp(op, "-") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_sub);
    }
    else if (strcmp(op, "/") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_div);
    }
    else if (strcmp(op, "%") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_mod);
    }
    else if (strcmp(op, "*") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_mul);
    }
    else if (strcmp(op, "**") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_pow);
    }
    else if (strcmp(op, "&") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_and);
    }
    else if (strcmp(op, "|") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_or);
    }
    else if (strcmp(op, ">>") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_sar);
    }
    else if (strcmp(op, ">>>") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_shr);
    }
    else if (strcmp(op, "<<") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_shl);
    }
    else if (strcmp(op, "^") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_xor);
    }
    else if (strcmp(op, "==") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_eq);
    }
    else if (strcmp(op, "===") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_strict_eq);
    }
    else if (strcmp(op, "!=") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_neq);
    }
    else if (strcmp(op, "!==") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_strict_neq);
    }
    else if (strcmp(op, "pin") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_private_in);
    }
    else if (strcmp(op, "in") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_in);
    }
    else if (strcmp(op, "instanceof") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_instanceof);
    }
    else if (strcmp(op, ">") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_gt);
    }
    else if (strcmp(op, "<") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_lt);
    }
    else if (strcmp(op, ">=") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_gte);
    }
    else if (strcmp(op, "<=") == 0)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_lte);
    }
    else
    {
      fprintf(stderr, "TODO: binop %s\n", op);
      exit(1);
    }
  }
  else if (isTag(rval, "FieldRead"))
  {
    IridiumSEXP *receiver = rval->args[0];
    currTarget = lowerToStack(ctx, currTarget, receiver);
    IridiumSEXP *field = rval->args[1];
    ensureTag(field, "String");
    JSAtom fieldAtom = JS_NewAtom(ctx, getFlagString(field, "IridiumPrimitive"));
    return pushOP32(ctx, currTarget, OP_get_field, fieldAtom);
  }
  else if (isTag(rval, "JSComputedFieldRead"))
  {
    IridiumSEXP *receiver = rval->args[0];
    currTarget = lowerToStack(ctx, currTarget, receiver);
    IridiumSEXP *field = rval->args[1];
    currTarget = lowerToStack(ctx, currTarget, field);
    return pushOP(ctx, currTarget, OP_get_array_el);
  }
  else if (isTag(rval, "JSObjectProp"))
  {
    IridiumSEXP *val = rval->args[1];
    currTarget = lowerToStack(ctx, currTarget, val);

    IridiumSEXP *field = rval->args[0];
    ensureTag(field, "String");
    JSAtom fieldAtom = JS_NewAtom(ctx, getFlagString(field, "IridiumPrimitive"));
    return pushOP32(ctx, currTarget, OP_define_field, fieldAtom);
  }
  else if (isTag(rval, "JSComputedObjectProp"))
  {
    IridiumSEXP *field = rval->args[0];
    currTarget = lowerToStack(ctx, currTarget, field);

    IridiumSEXP *val = rval->args[1];
    currTarget = lowerToStack(ctx, currTarget, val);

    currTarget = pushOP(ctx, currTarget, OP_define_array_el);
    return pushOP(ctx, currTarget, OP_drop);
  }

  else if (isTag(rval, "JSObjectMethod"))
  {
    IridiumSEXP *val = rval->args[1];
    currTarget = lowerToStack(ctx, currTarget, val);

    IridiumSEXP *field = rval->args[0];
    ensureTag(field, "String");
    JSAtom fieldAtom = JS_NewAtom(ctx, getFlagString(field, "IridiumPrimitive"));
    
    uint8_t op_flag;
    if (hasFlag(rval, "METHOD"))
    {
      op_flag = OP_DEFINE_METHOD_METHOD | OP_DEFINE_METHOD_ENUMERABLE;
    }
    else if (hasFlag(rval, "GET"))
    {
      op_flag = OP_DEFINE_METHOD_GETTER | OP_DEFINE_METHOD_ENUMERABLE;
    }
    else if (hasFlag(rval, "SET"))
    {
      op_flag = OP_DEFINE_METHOD_SETTER | OP_DEFINE_METHOD_ENUMERABLE;
    }
    else
    {
      fprintf(stderr, "TODO: JSObjectMethod invalid flag\n");
      exit(1);
    }
    currTarget = pushOP32Flags(ctx, currTarget, OP_define_method, fieldAtom, op_flag);
    return currTarget;
  }

  else if (isTag(rval, "JSObject"))
  {
    return pushOP(ctx, currTarget, OP_object);
    // for (int i = 0; i < rval->numArgs; i++)
    // {
    //   IridiumSEXP *ele = rval->args[i];
    //   if (isTag(ele, "JSObjectProp") || isTag(ele, "JSComputedObjectProp") || isTag(ele, "JSObjectMethod"))
    //   {
    //     currTarget = lowerToStack(ctx, currTarget, ele);
    //   }
    //   else
    //   {
    //     fprintf(stderr, "TODO: unhandled Object Init Element: %s\n", ele->tag);
    //     exit(1);
    //   }
    // }
  }
  else if (isTag(rval, "PoolBinding"))
  {
    uint32_t poolOffset = getFlagNumber(rval, "REFIDX");
    currTarget = pushOP32(ctx, currTarget, OP_fclosure, poolOffset);
    currTarget->lambdaPoolReference = true;
    return currTarget;
  }
  else if (isTag(rval, "JSClass"))
  {
    IridiumSEXP *className = rval->args[0];
    ensureTag(className, "String");
    JSAtom classNameAtom = JS_NewAtom(ctx, getFlagString(className, "IridiumPrimitive"));

    currTarget = lowerToStack(ctx, currTarget, rval->args[1]);

    // Instead of creating a closure, we push the constructor bytecode directly onto the stack
    {
      IridiumSEXP *constructorClosure = rval->args[2];
      uint32_t poolOffset = getFlagNumber(constructorClosure, "REFIDX");
      currTarget = pushOP32(ctx, currTarget, OP_push_const, poolOffset);
      currTarget->lambdaPoolReference = true;
    }

    uint8_t flags = hasFlag(rval, "Derived") ? 1 : 0;
    currTarget = pushOP32Flags(ctx, currTarget, OP_define_class, classNameAtom, flags);
    // Class Flags, the bytecode itself is 5 + 1 bytes (1 byte OPcode + 4 byte name + 1 byte flags)


    // Set home object for classPropInitClosure
    IridiumSEXP *classPropInitClos = rval->args[3];
    currTarget = lowerToStack(ctx, currTarget, classPropInitClos);
    currTarget = pushOP(ctx, currTarget, OP_set_home_object);
    currTarget = pushOP(ctx, currTarget, OP_drop); // <- Drops the closure, not the prototype: set does not pop

    // Define methods on the prototype
    IridiumSEXP *methodList = rval->args[4];
    for (int i = 0; i < methodList->numArgs; ++i)
    {
      IridiumSEXP *methodName = methodList->args[i]->args[0];
      IridiumSEXP *methodLambda = methodList->args[i]->args[1];
      IridiumSEXP *methodKind = methodList->args[i]->args[2];
      assert(isTag(methodKind, "String"));
      char * kindStr = getFlagString(methodKind, "IridiumPrimitive");
      uint8_t op_flag;

      if (strcmp(kindStr, "METHOD") == 0) {
        op_flag = OP_DEFINE_METHOD_METHOD;
      } else if (strcmp(kindStr, "GET") == 0) {
        op_flag = OP_DEFINE_METHOD_GETTER;
      } else if (strcmp(kindStr, "SET") == 0) {
        op_flag = OP_DEFINE_METHOD_SETTER;
      } else {
        fprintf(stderr, "TODO: Classmethod flag is invalid\n");
        exit(1);
      }

      if (isTag(methodName, "String"))
      {
        // Lower the method on the stack
        currTarget = lowerToStack(ctx, currTarget, methodLambda);

        // Get the method name atom
        ensureTag(methodName, "String");
        JSAtom fieldAtom = JS_NewAtom(ctx, getFlagString(methodName, "IridiumPrimitive"));

        // Define method on the prototype
        currTarget = pushOP32Flags(ctx, currTarget, OP_define_method, fieldAtom, op_flag);
      }
      else if (isTag(methodName, "EnvRead"))
      {
        // Lower the computed name of the function on stack
        currTarget = lowerToStack(ctx, currTarget, methodName);

        // Lower the closure on the stack
        currTarget = lowerToStack(ctx, currTarget, methodLambda);

        // Define method on the prototype
        currTarget = pushOPFlags(ctx, currTarget, OP_define_method_computed, op_flag);
      }
      else if (isTag(methodName, "Private"))
      {
        // Get the lambda on the stack
        currTarget = lowerToStack(ctx, currTarget, methodLambda);

        // Set name
        JSAtom privateMethodNameAtom = JS_NewAtom(ctx, getFlagString(methodName, "IridiumPrimitive"));
        currTarget = pushOP32(ctx, currTarget, OP_set_name, privateMethodNameAtom);

        // Set home to be the prototype
        currTarget = pushOP(ctx, currTarget, OP_set_home_object); // sets the home to the prototype

        currTarget = pushOP(ctx, currTarget, OP_drop); // <- Drop the closure from stack
      }
    }

    // Define methods on the constructor
    currTarget = pushOP(ctx, currTarget, OP_swap); // ctr proto -> proto ctr
    IridiumSEXP *staticMethodList = rval->args[5];
    for (int i = 0; i < staticMethodList->numArgs; ++i)
    {
      IridiumSEXP *methodName = staticMethodList->args[i]->args[0];
      IridiumSEXP *methodLambda = staticMethodList->args[i]->args[1];
      IridiumSEXP *methodKind = staticMethodList->args[i]->args[2];
      assert(isTag(methodKind, "String"));
      char * kindStr = getFlagString(methodKind, "IridiumPrimitive");
      uint8_t op_flag;

      if (strcmp(kindStr, "METHOD") == 0) {
        op_flag = OP_DEFINE_METHOD_METHOD;
      } else if (strcmp(kindStr, "GET") == 0) {
        op_flag = OP_DEFINE_METHOD_GETTER;
      } else if (strcmp(kindStr, "SET") == 0) {
        op_flag = OP_DEFINE_METHOD_SETTER;
      } else {
        fprintf(stderr, "TODO: Classmethod flag is invalid\n");
        exit(1);
      }
      
      if (isTag(methodName, "String"))
      {
        // Lower the method on the stack
        currTarget = lowerToStack(ctx, currTarget, methodLambda);

        // Get the method name atom
        ensureTag(methodName, "String");
        JSAtom fieldAtom = JS_NewAtom(ctx, getFlagString(methodName, "IridiumPrimitive"));

        // Define method on the prototype
        currTarget = pushOP32Flags(ctx, currTarget, OP_define_method, fieldAtom, op_flag);
      }
      else if (isTag(methodName, "EnvRead"))
      {
        // Lower the computed name of the function on stack
        currTarget = lowerToStack(ctx, currTarget, methodName);

        // Lower the closure on the stack
        currTarget = lowerToStack(ctx, currTarget, methodLambda);

        // Define method on the prototype
        currTarget = pushOPFlags(ctx, currTarget, OP_define_method_computed, op_flag);
      }
      else if (isTag(methodName, "Private"))
      {
        // Get the lambda on the stack
        currTarget = lowerToStack(ctx, currTarget, methodLambda);

        // Set name
        JSAtom privateMethodNameAtom = JS_NewAtom(ctx, getFlagString(methodName, "IridiumPrimitive"));
        currTarget = pushOP32(ctx, currTarget, OP_set_name, privateMethodNameAtom);

        // Set home to be the prototype
        currTarget = pushOP(ctx, currTarget, OP_set_home_object); // sets the home to the prototype

        currTarget = pushOP(ctx, currTarget, OP_drop); // <- Drop the closure from stack
      }
    }
    currTarget = pushOP(ctx, currTarget, OP_swap); // proto ctr -> ctr proto

    // BrandPrototype
    if (hasFlag(rval, "BrandPrototype"))
    {
      currTarget = pushOP(ctx, currTarget, OP_dup);
      currTarget = pushOP(ctx, currTarget, OP_null);
      currTarget = pushOP(ctx, currTarget, OP_swap);
      currTarget = pushOP(ctx, currTarget, OP_add_brand);
    }

    currTarget = pushOP(ctx, currTarget, OP_drop);

    // BrandPrototype
    if (hasFlag(rval, "BrandConstructor"))
    {
      currTarget = pushOP(ctx, currTarget, OP_dup);
      currTarget = pushOP(ctx, currTarget, OP_dup);
      currTarget = pushOP(ctx, currTarget, OP_add_brand);
    }

    // Static Prop Init
    IridiumSEXP *staticPropInitClosure = rval->args[6];
    currTarget = pushOP(ctx, currTarget, OP_dup);
    currTarget = lowerToStack(ctx, currTarget, staticPropInitClosure);
    currTarget = pushOP(ctx, currTarget, OP_set_home_object);
    currTarget = pushOP16(ctx, currTarget, OP_call_method, 0);
    currTarget = pushOP(ctx, currTarget, OP_drop);

    return currTarget;
  }
  else if (isTag(rval, "JSArray"))
  {
    for (int i = 0; i < rval->numArgs; i++)
    {
      currTarget = lowerToStack(ctx, currTarget, rval->args[i]);
    }
    return pushOP16(ctx, currTarget, OP_array_from, rval->numArgs);
  }
  else if (isTag(rval, "Private"))
  {
    char *data = getFlagString(rval, "IridiumPrimitive");
    JSAtom strAtom = JS_NewAtom(ctx, data);
    return pushOP32(ctx, currTarget, OP_private_symbol, strAtom);
  }
  else if (isTag(rval, "JSPrivateFieldRead"))
  {
    currTarget = lowerToStack(ctx, currTarget, rval->args[0]);
    currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
    return pushOP(ctx, currTarget, OP_get_private_field);
  }
  else if (isTag(rval, "JSSuperFieldRead"))
  {
    currTarget = lowerToStack(ctx, currTarget, rval->args[0]);
    currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
    currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
    return pushOP(ctx, currTarget, OP_get_super_value);
  }
  else if (isTag(rval, "JSSuperFieldWrite"))
  {
    currTarget = lowerToStack(ctx, currTarget, rval->args[0]);
    currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
    currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
    currTarget = lowerToStack(ctx, currTarget, rval->args[3]);
    return pushOP(ctx, currTarget, OP_put_super_value);
  }
  else if (isTag(rval, "Null"))
  {
    return pushOP(ctx, currTarget, OP_null);
  }
  else if (isTag(rval, "BitInt"))
  {
    char *str = getFlagString(rval, "IridiumPrimitive");

    // char *endptr;

    // errno = 0; // Reset errno before call
    // int64_t value = strtoll(str, &endptr, 10);

    // if (errno == ERANGE)
    // {
    //   fprintf(stderr, "BIGINT: BitInt: Overflow/Underflow occurred\n");
    //   exit(1);
    // }
    // else if (endptr == str)
    // {
    //   fprintf(stderr, "BIGINT: BitInt: No digits were found\n");
    //   exit(1);
    // }

    // JSValue val = JS_NewBigInt64(ctx, value);
    // return pushOPConst(ctx, currTarget, OP_push_const, val);

    JSBigInt *r;
    JSValue val;
    r = js_bigint_from_string(ctx, str, 10);
    if (!r) {
      val = JS_ThrowOutOfMemory(ctx);
    }
    val = JS_CompactBigInt(ctx, r);
    return pushOPConst(ctx, currTarget, OP_push_const, val);
  }
  else if (isTag(rval, "Await"))
  {
    currTarget = lowerToStack(ctx, currTarget, rval->args[0]);
    return pushOP(ctx, currTarget, OP_await);
  }
  else if (isTag(rval, "Nope"))
  {
    return currTarget;
  }
  else if (isTag(rval, "FieldWrite"))
  {
    // Receiver
    IridiumSEXP *receiver = rval->args[0];
    currTarget = lowerToStack(ctx, currTarget, receiver);

    // Rval
    IridiumSEXP *valToPush = rval->args[2];
    currTarget = lowerToStack(ctx, currTarget, valToPush);
    currTarget = pushOP(ctx, currTarget, OP_dup);
    currTarget = pushOP(ctx, currTarget, OP_rot3r);

    // Field
    IridiumSEXP *field = rval->args[1];
    ensureTag(field, "String");
    JSAtom fieldAtom = JS_NewAtom(ctx, getFlagString(field, "IridiumPrimitive"));
    currTarget = pushOP32(ctx, currTarget, OP_put_field, fieldAtom);

    return currTarget;
  }
  else if (isTag(rval, "JSComputedFieldWrite"))
  {
    // Receiver
    IridiumSEXP *receiver = rval->args[0];
    currTarget = lowerToStack(ctx, currTarget, receiver);

    // Field
    IridiumSEXP *field = rval->args[1];
    currTarget = lowerToStack(ctx, currTarget, field);
    currTarget = pushOP(ctx, currTarget, OP_to_propkey);

    // Rval
    IridiumSEXP *assnVal = rval->args[2];
    currTarget = lowerToStack(ctx, currTarget, assnVal);

    // Receiver Field Rval -> Rval Receiver Field Rval
    currTarget = pushOP(ctx, currTarget, OP_insert3);

    currTarget = pushOP(ctx, currTarget, OP_put_array_el); // Receiver Field Rval
  }
  else
  {
    fprintf(stderr, "TODO: unhandled RVal: %s\n", rval->tag);
    exit(1);
  }
  return currTarget;
}

BCLList *handleEnvWrite(JSContext *ctx, BCLList *currTarget, IridiumSEXP *currStmt, bool saveResToStack)
{
  bool safe = getFlagBoolean(currStmt, "SAFE");
  bool thisInit = getFlagBoolean(currStmt, "THISINIT");
  bool isStrict = !hasFlag(currStmt, "SLOPPY");

  IridiumSEXP *loc = currStmt->args[0];
  IridiumSEXP *rval = currStmt->args[1];

  // Store something on the stack
  currTarget = lowerToStack(ctx, currTarget, rval);
  // Store that something where its required
  return storeWhatevesOnTheStack(ctx, loc, currTarget, safe, thisInit, isStrict, saveResToStack);
}

BCLList *handleIriStmt(JSContext *ctx, BCLList *currTarget, IridiumSEXP *currStmt)
{
  if (isTag(currStmt, "EnvWrite"))
  {
    currTarget = handleEnvWrite(ctx, currTarget, currStmt, false);
  }
  else if (isTag(currStmt, "FieldWrite") || isTag(currStmt, "JSComputedFieldWrite"))
  {
    currTarget = lowerToStack(ctx, currTarget, currStmt);
    return pushOP(ctx, currTarget, OP_drop);
  }
  else if (isTag(currStmt, "JSForInNext"))
  {
    currTarget = lowerToStack(ctx, currTarget, currStmt->args[0]);
    currTarget = pushOP(ctx, currTarget, OP_for_in_next);

    IridiumSEXP *doneTarget = currStmt->args[1];
    assert(isTag(doneTarget, "EnvBinding"));
    int doneTargetIDX = getFlagNumber(doneTarget, "REFIDX");

    IridiumSEXP *nextValTarget = currStmt->args[2];
    assert(isTag(nextValTarget, "EnvBinding"));
    int nextValTargetIDX = getFlagNumber(nextValTarget, "REFIDX");

    currTarget = pushOP16(ctx, currTarget, OP_put_loc, doneTargetIDX);    // top of the stack contains <loop-done>
    currTarget = pushOP16(ctx, currTarget, OP_put_loc, nextValTargetIDX); // top - 1 of the stack contains <loop-next>
    return pushOP(ctx, currTarget, OP_drop);                              // drop enum_obj
  }
  else if (isTag(currStmt, "JSForOfStart"))
  {
    // Push obj onto the stack
    currTarget = lowerToStack(ctx, currTarget, currStmt->args[0]);

    // obj -> enum_obj iterator_method catch_offset
    return pushOP(ctx, currTarget, OP_for_of_start);
  }
  else if (isTag(currStmt, "JSForInStart"))
  {
    // Push obj onto the stack
    currTarget = lowerToStack(ctx, currTarget, currStmt->args[0]);

    // obj -> enum_obj
    currTarget = pushOP(ctx, currTarget, OP_for_in_start);
    IridiumSEXP *stackLocation = currStmt->args[1];
    int stackLocationIDX = getFlagNumber(stackLocation, "REFIDX");
    if (isTag(stackLocation, "EnvBinding"))
    {
      currTarget = pushOP16(ctx, currTarget, OP_put_loc_check, stackLocationIDX);
    }
    else if (isTag(stackLocation, "RemoteEnvBinding"))
    {
      currTarget = pushOP16(ctx, currTarget, OP_put_var_ref_check, stackLocationIDX);
    }
    else
    {
      fprintf(stderr, "TODO: Expected a EnvBinding or RemoteEnvBinding!!");
    }
  }
  else if (isTag(currStmt, "JSForOfNext"))
  {
    // [it, meth, off] -> [it, meth, off, result, done]
    currTarget = pushOP16(ctx, currTarget, OP_for_of_next, 0);

    // Store <for-of-loop-done> = done
    // Store <for-of-loop-next> = result
    assert(currStmt->numArgs == 2);
    for (int i = 0; i < currStmt->numArgs; i++)
    {
      IridiumSEXP *stackLocation = currStmt->args[i];
      int stackLocationIDX = getFlagNumber(stackLocation, "REFIDX");
      if (isTag(stackLocation, "EnvBinding"))
      {
        currTarget = pushOP16(ctx, currTarget, OP_put_loc_check, stackLocationIDX);
      }
      else if (isTag(stackLocation, "RemoteEnvBinding"))
      {
        currTarget = pushOP16(ctx, currTarget, OP_put_var_ref_check, stackLocationIDX);
      }
      else
      {
        fprintf(stderr, "TODO: Expected a EnvBinding or RemoteEnvBinding!!");
      }
    }
  }

  else if (isTag(currStmt, "JSADDBRAND"))
  {
    currTarget = lowerToStack(ctx, currTarget, currStmt->args[0]);
    currTarget = lowerToStack(ctx, currTarget, currStmt->args[1]);
    return pushOP(ctx, currTarget, OP_add_brand);
  }
  else if (isTag(currStmt, "Throw"))
  {
    currTarget = lowerToStack(ctx, currTarget, currStmt->args[0]);
    return pushOP(ctx, currTarget, OP_throw);
  }
  else if (isTag(currStmt, "JSCheckConstructor"))
  {
    return pushOP(ctx, currTarget, OP_check_ctor);
  }
  else if (isTag(currStmt, "JSCatchContext"))
  {
    IridiumSEXP *loc = currStmt->args[0];
    ensureTag(loc, "EnvBinding");
    int refIdx = getFlagNumber(loc, "REFIDX");
    return pushOP16(ctx, currTarget, OP_put_loc, refIdx);
  }
  else if (isTag(currStmt, "PushForOfCatchContext"))
  {
    return lowerToStack(ctx, currTarget, currStmt->args[0]);
  }
  else if (isTag(currStmt, "IfJump"))
  {
    // Push check to stack
    currTarget = lowerToStack(ctx, currTarget, currStmt->args[0]);

    bool isNot = hasFlag(currStmt, "NOT");

    // Jmp to TRUE if stack value is true
    currTarget = pushOP32(ctx, currTarget, isNot ? OP_if_false : OP_if_true, getFlagNumber(currStmt, "IDX"));

    return currTarget;
  }
  else if (isTag(currStmt, "IfElseJump"))
  {
    // Push check to stack
    currTarget = lowerToStack(ctx, currTarget, currStmt->args[0]);

    // Jmp to TRUE if stack value is true
    currTarget = pushOP32(ctx, currTarget, OP_if_true, getFlagNumber(currStmt, "TRUE"));

    // Jmp to FALSE if stack value is false
    currTarget = pushOP32(ctx, currTarget, OP_goto, getFlagNumber(currStmt, "FALSE"));

    return currTarget;
  }
  else if (isTag(currStmt, "JSModuleStart"))
  {
    currTarget = pushOP(ctx, currTarget, OP_push_this);
    currTarget = pushOP8(ctx, currTarget, OP_if_false8, 2);
    return pushOP(ctx, currTarget, OP_return_undef);
  }
  else if (isTag(currStmt, "JSModuleEnd"))
  {
    currTarget = pushOP(ctx, currTarget, OP_undefined);
    return pushOP(ctx, currTarget, OP_return_async);
  }
  else if (isTag(currStmt, "InvokeFinalizer"))
  {
    return pushOP32(ctx, currTarget, OP_gosub, getFlagNumber(currStmt, "IDX"));
  }
  else if (isTag(currStmt, "Goto"))
  {
    return pushOP32(ctx, currTarget, OP_goto, getFlagNumber(currStmt, "IDX"));
  }
  else if (isTag(currStmt, "PushCatchContext"))
  {
    return pushOP32(ctx, currTarget, OP_catch, getFlagNumber(currStmt, "IDX"));
  }
  else if (isTag(currStmt, "PopCatchContext"))
  {
    return pushOP(ctx, currTarget, OP_drop);
  }
  else if (isTag(currStmt, "Return"))
  {
    currTarget = lowerToStack(ctx, currTarget, currStmt->args[0]);
    return pushOP(ctx, currTarget, OP_return);
  }
  else if (isTag(currStmt, "ReturnAsync"))
  {
    currTarget = lowerToStack(ctx, currTarget, currStmt->args[0]);
    return pushOP(ctx, currTarget, OP_return_async);
  }
  else if (isTag(currStmt, "NOP"))
  {
    return currTarget;
  }
  else if (isTag(currStmt, "JSTHISINIT"))
  {
    currTarget = pushOP(ctx, currTarget, OP_push_this);
    IridiumSEXP *thisLoc = currStmt->args[0];
    ensureTag(thisLoc, "EnvBinding");
    int refIdx = getFlagNumber(thisLoc, "REFIDX");
    return pushOP16(ctx, currTarget, OP_put_loc, refIdx);
  }
  else if (isTag(currStmt, "JSMODULEMETAINIT"))
  {
    currTarget = pushOP8(ctx, currTarget, OP_special_object, 6);

    IridiumSEXP *thisLoc = currStmt->args[0];
    ensureTag(thisLoc, "EnvBinding");
    int refIdx = getFlagNumber(thisLoc, "REFIDX");

    return pushOP16(ctx, currTarget, OP_put_loc, refIdx);
  }
  else if (isTag(currStmt, "JSARGUMENTSINIT"))
  {
    currTarget = pushOP8(ctx, currTarget, OP_special_object, 0);

    IridiumSEXP *argsLoc = currStmt->args[0];
    ensureTag(argsLoc, "EnvBinding");
    int refIdx = getFlagNumber(argsLoc, "REFIDX");

    return pushOP16(ctx, currTarget, OP_put_loc, refIdx);
  }
  else if (isTag(currStmt, "JSMARGUMENTSINIT"))
  {
    currTarget = pushOP8(ctx, currTarget, OP_special_object, 1);

    IridiumSEXP *argsLoc = currStmt->args[0];
    ensureTag(argsLoc, "EnvBinding");
    int refIdx = getFlagNumber(argsLoc, "REFIDX");

    return pushOP16(ctx, currTarget, OP_put_loc, refIdx);
  }
  else if (isTag(currStmt, "CallSite"))
  {
    currTarget = lowerToStack(ctx, currTarget, currStmt);
    return pushOP(ctx, currTarget, OP_drop);
  }
  else if (isTag(currStmt, "JSSUPEROBJINIT"))
  {
    currTarget = pushOP8(ctx, currTarget, OP_special_object, 4);
    currTarget = pushOP(ctx, currTarget, OP_get_super);
    IridiumSEXP *targetBinding = currStmt->args[0];
    ensureTag(targetBinding, "EnvBinding");
    int refIdx = getFlagNumber(targetBinding, "REFIDX");
    return pushOP16(ctx, currTarget, OP_put_loc, refIdx);
  }
  else if (isTag(currStmt, "JSNEWTARGETINIT"))
  {
    currTarget = pushOP8(ctx, currTarget, OP_special_object, 3);
    IridiumSEXP *targetBinding = currStmt->args[0];
    ensureTag(targetBinding, "EnvBinding");
    int refIdx = getFlagNumber(targetBinding, "REFIDX");
    return pushOP16(ctx, currTarget, OP_put_loc, refIdx);
  }
  else if (isTag(currStmt, "JSSUPERCTRINIT"))
  {
    currTarget = pushOP8(ctx, currTarget, OP_special_object, 2);
    currTarget = pushOP(ctx, currTarget, OP_get_super);
    IridiumSEXP *targetBinding = currStmt->args[0];
    ensureTag(targetBinding, "EnvBinding");
    int refIdx = getFlagNumber(targetBinding, "REFIDX");
    return pushOP16(ctx, currTarget, OP_put_loc, refIdx);
  }
  else if (isTag(currStmt, "JSHOMEOBJ"))
  {
    currTarget = pushOP8(ctx, currTarget, OP_special_object, 4);
    IridiumSEXP *targetBinding = currStmt->args[0];
    ensureTag(targetBinding, "EnvBinding");
    int refIdx = getFlagNumber(targetBinding, "REFIDX");
    return pushOP16(ctx, currTarget, OP_put_loc, refIdx);
  }
  else if (isTag(currStmt, "JSToObject"))
  {
    currTarget = lowerToStack(ctx, currTarget, currStmt->args[0]);
    currTarget = pushOP(ctx, currTarget, OP_to_object);

    bool safe = getFlagBoolean(currStmt, "SAFE");
    bool thisInit = getFlagBoolean(currStmt, "THISINIT");
    bool isStrict = !hasFlag(currStmt, "SLOPPY");

    IridiumSEXP *loc = currStmt->args[1];
    currTarget = storeWhatevesOnTheStack(ctx, loc, currTarget, safe, thisInit, isStrict, false);
  }
  else if (isTag(currStmt, "JSPrivateFieldWrite"))
  {
    currTarget = lowerToStack(ctx, currTarget, currStmt->args[0]);
    currTarget = lowerToStack(ctx, currTarget, currStmt->args[1]);
    currTarget = lowerToStack(ctx, currTarget, currStmt->args[2]);
    return pushOP(ctx, currTarget, OP_define_private_field);
  }
  else if (isTag(currStmt, "JSInitialYield"))
  {
    return pushOP(ctx, currTarget, OP_initial_yield);
  }
  else if (isTag(currStmt, "JSClassMethodDefine"))
  {
    IridiumSEXP *where = currStmt->args[0];
    currTarget = lowerToStack(ctx, currTarget, where);

    IridiumSEXP *what = currStmt->args[2];
    currTarget = lowerToStack(ctx, currTarget, what);

    IridiumSEXP *field = currStmt->args[1];
    ensureTag(field, "String");
    JSAtom fieldAtom = JS_NewAtom(ctx, getFlagString(field, "IridiumPrimitive"));
    uint8_t op_flag = OP_DEFINE_METHOD_METHOD | OP_DEFINE_METHOD_ENUMERABLE;
    currTarget = pushOP32Flags(ctx, currTarget, OP_define_method, fieldAtom, op_flag);
    return currTarget;
  }
  else if (isTag(currStmt, "JSCopyDataProperties"))
  {
    // exc_obj
    IridiumSEXP *exc_obj = currStmt->args[0];
    currTarget = lowerToStack(ctx, currTarget, exc_obj);

    // source
    IridiumSEXP *source = currStmt->args[1];
    currTarget = lowerToStack(ctx, currTarget, source);

    // target
    IridiumSEXP *target = currStmt->args[2];
    currTarget = lowerToStack(ctx, currTarget, target);

    // OP_copy_data_properties
    currTarget = pushOP16(ctx, currTarget, OP_copy_data_properties, 68);

    bool safe = getFlagBoolean(currStmt, "SAFE");
    bool thisInit = getFlagBoolean(currStmt, "THISINIT");
    bool isStrict = !hasFlag(currStmt, "SLOPPY");

    IridiumSEXP *loc = currStmt->args[3];
    currTarget = storeWhatevesOnTheStack(ctx, loc, currTarget, safe, thisInit, isStrict, false);

    currTarget = pushOP(ctx, currTarget, OP_drop);
    return pushOP(ctx, currTarget, OP_drop);
  }
  else if (isTag(currStmt, "JSIteratorClose"))
  {
    return pushOP(ctx, currTarget, OP_iterator_close);
  }
  else if (isTag(currStmt, "Ret"))
  {
    return pushOP(ctx, currTarget, OP_ret);
  }
  else if (isTag(currStmt, "Yield"))
  {
    currTarget = lowerToStack(ctx, currTarget, currStmt->args[0]);
    currTarget = pushOP(ctx, currTarget, OP_yield);

    IridiumSEXP *stackLocation = currStmt->args[1];
    int stackLocationIDX = getFlagNumber(stackLocation, "REFIDX");
    if (isTag(stackLocation, "EnvBinding"))
    {
      currTarget = pushOP16(ctx, currTarget, OP_put_loc_check, stackLocationIDX);
    }
    else if (isTag(stackLocation, "RemoteEnvBinding"))
    {
      currTarget = pushOP16(ctx, currTarget, OP_put_var_ref_check, stackLocationIDX);
    }
    else
    {
      fprintf(stderr, "YIELD: Expected a EnvBinding or RemoteEnvBinding!!");
    }

    stackLocation = currStmt->args[2];
    stackLocationIDX = getFlagNumber(stackLocation, "REFIDX");
    if (isTag(stackLocation, "EnvBinding"))
    {
      currTarget = pushOP16(ctx, currTarget, OP_put_loc_check, stackLocationIDX);
    }
    else if (isTag(stackLocation, "RemoteEnvBinding"))
    {
      currTarget = pushOP16(ctx, currTarget, OP_put_var_ref_check, stackLocationIDX);
    }
    else
    {
      fprintf(stderr, "YIELD: Expected a EnvBinding or RemoteEnvBinding!!");
    }
    
  }
  else if (isTag(currStmt, "JSSloppyDeclarationCheck"))
  {
    uint8_t check_flag = 0, define_flag = 0;

#define DEFINE_GLOBAL_LEX_VAR (1 << 7)
#define DEFINE_GLOBAL_FUNC_VAR (1 << 6)

    if (hasFlag(currStmt, "JSLET"))
    {
      check_flag |= DEFINE_GLOBAL_LEX_VAR;
      define_flag |= DEFINE_GLOBAL_LEX_VAR;
      define_flag |= JS_PROP_WRITABLE;
    }
    else if (hasFlag(currStmt, "JSCONST"))
    {
      check_flag |= DEFINE_GLOBAL_LEX_VAR;
      define_flag |= DEFINE_GLOBAL_LEX_VAR;
    }
    else if (hasFlag(currStmt, "JSVAR"))
    {
      // Redundant...
      check_flag = 0;
      check_flag = 0;
    }
    else
    {
      fprintf(stderr, "TODO: JSSloppyDeclarationCheck invalid flag config\n");
      exit(1);
    }

    char *name = getFlagString(currStmt, "NAME");
    currTarget = pushOP32Flags(ctx, currTarget, OP_check_define_var, JS_NewAtom(ctx, name), check_flag);
    currTarget = pushOP32Flags(ctx, currTarget, OP_define_var, JS_NewAtom(ctx, name), define_flag);

    return currTarget;
  }
  else if (isTag(currStmt, "JSFuncDecl"))
  {
    IridiumSEXP *loc = currStmt->args[0];
    IridiumSEXP *closure = currStmt->args[1];

    if (isTag(loc, "GlobalBinding"))
    {
      char *name = getFlagString(loc, "NAME");
      currTarget = pushOP32Flags(ctx, currTarget, OP_check_define_var, JS_NewAtom(ctx, name), 64);
      currTarget = lowerToStack(ctx, currTarget, closure);
      currTarget = pushOP32Flags(ctx, currTarget, OP_define_func, JS_NewAtom(ctx, name), 0);
    }
    else if (isTag(loc, "RemoteEnvBinding"))
    {
      currTarget = lowerToStack(ctx, currTarget, closure);
      int refIdx = getFlagNumber(loc, "REFIDX");
      currTarget = pushOP16(ctx, currTarget, OP_put_var_ref, refIdx);
    }
    else if (isTag(loc, "EnvBinding"))
    {
      currTarget = lowerToStack(ctx, currTarget, closure);
      int refIdx = getFlagNumber(loc, "REFIDX");
      currTarget = pushOP16(ctx, currTarget, OP_put_loc, refIdx);
    }
    else
    {
      fprintf(stderr, "TODO: unhandled JSFuncDecl case\n");
      exit(1);
    }
  }
  else if (isTag(currStmt, "JSAppend"))
  {
    currTarget = lowerToStack(ctx, currTarget, currStmt->args[0]); // tmp
    currTarget = lowerToStack(ctx, currTarget, currStmt->args[1]); // insertionIdx
    currTarget = lowerToStack(ctx, currTarget, currStmt->args[2]); // spreadVal
    currTarget = pushOP(ctx, currTarget, OP_append);

    bool safe = getFlagBoolean(currStmt, "SAFE");
    bool thisInit = getFlagBoolean(currStmt, "THISINIT");
    bool isStrict = !hasFlag(currStmt, "SLOPPY");

    { // InsertionIdxLoc
      IridiumSEXP *insertionLoc = currStmt->args[3];
      currTarget = storeWhatevesOnTheStack(ctx, insertionLoc, currTarget, safe, thisInit, isStrict, false);
    }

    { // tempLoc
      IridiumSEXP *tmpLoc = currStmt->args[4];
      currTarget = storeWhatevesOnTheStack(ctx, tmpLoc, currTarget, safe, thisInit, isStrict, false);
    }

  }
  else if (isTag(currStmt, "JSDefineObjProp"))
  {
    IridiumSEXP *obj  = currStmt->args[0];
    currTarget = lowerToStack(ctx, currTarget, obj);
    IridiumSEXP *field = currStmt->args[1];
    IridiumSEXP *val  = currStmt->args[2];

    if (isTag(field, "String")) {
      currTarget = lowerToStack(ctx, currTarget, val);
      JSAtom fieldAtom = JS_NewAtom(ctx, getFlagString(field, "IridiumPrimitive"));
      currTarget = pushOP32(ctx, currTarget, OP_define_field, fieldAtom);
    }
    else
    {
      currTarget = lowerToStack(ctx, currTarget, field);
      currTarget = lowerToStack(ctx, currTarget, val);
      currTarget = pushOP(ctx, currTarget, OP_define_array_el);
      currTarget = pushOP(ctx, currTarget, OP_drop);
    }

    bool safe = getFlagBoolean(currStmt, "SAFE");
    bool thisInit = getFlagBoolean(currStmt, "THISINIT");
    bool isStrict = !hasFlag(currStmt, "SLOPPY");

    { // tempLoc
      IridiumSEXP *loc = currStmt->args[3];
      currTarget = storeWhatevesOnTheStack(ctx, loc, currTarget, safe, thisInit, isStrict, false);
    }
  }
  else if (isTag(currStmt, "JSDefineObjMethod"))
  {
    uint8_t op_flag;
    if (hasFlag(currStmt, "METHOD"))
    {
      op_flag = OP_DEFINE_METHOD_METHOD | OP_DEFINE_METHOD_ENUMERABLE;
    }
    else if (hasFlag(currStmt, "GET"))
    {
      op_flag = OP_DEFINE_METHOD_GETTER | OP_DEFINE_METHOD_ENUMERABLE;
    }
    else if (hasFlag(currStmt, "SET"))
    {
      op_flag = OP_DEFINE_METHOD_SETTER | OP_DEFINE_METHOD_ENUMERABLE;
    }
    else
    {
      fprintf(stderr, "TODO: JSDefineObjMethod invalid flag\n");
      exit(1);
    }
    
    IridiumSEXP *obj  = currStmt->args[0];
    currTarget = lowerToStack(ctx, currTarget, obj);
    IridiumSEXP *field = currStmt->args[1];
    IridiumSEXP *val  = currStmt->args[2];

    
    if (isTag(field, "String")) {
      currTarget = lowerToStack(ctx, currTarget, val);
      JSAtom fieldAtom = JS_NewAtom(ctx, getFlagString(field, "IridiumPrimitive"));
      currTarget = pushOP32Flags(ctx, currTarget, OP_define_method, fieldAtom, op_flag);
    }
    else
    {
      currTarget = lowerToStack(ctx, currTarget, field);
      currTarget = lowerToStack(ctx, currTarget, val);
      currTarget = pushOPFlags(ctx, currTarget, OP_define_method_computed, op_flag);
    }

    bool safe = getFlagBoolean(currStmt, "SAFE");
    bool thisInit = getFlagBoolean(currStmt, "THISINIT");
    bool isStrict = !hasFlag(currStmt, "SLOPPY");

    { // tempLoc
      IridiumSEXP *loc = currStmt->args[3];
      currTarget = storeWhatevesOnTheStack(ctx, loc, currTarget, safe, thisInit, isStrict, false);
    }
  }
  else
  {
    fprintf(stderr, "TODO: unhandled tag: %s\n", currStmt->tag);
    exit(1);
  }
  return currTarget;
}

BCLList *handleBB(JSContext *ctx, BCLList *currTarget, IridiumSEXP *bb)
{
  ensureTag(bb, "BB");

  for (int stmtIDX = 0; stmtIDX < bb->numArgs; stmtIDX++)
  {
    IridiumSEXP *currStmt = bb->args[stmtIDX];
    currTarget = handleIriStmt(ctx, currTarget, currStmt);
  }

  return currTarget;
}

// ============== Code Generation ============== //

// ============== Helper Functions ============== //

int getPoolSize(BCLList *bcList)
{
  if (bcList)
  {
    if (bcList->hasPoolData)
    {
      return 1 + getPoolSize(bcList->next);
    }
    return getPoolSize(bcList->next);
  }
  return 0;
}

int getBCSize(BCLList *bcList)
{
  if (bcList)
  {
    return short_opcode_info(bcList->bc).size + getBCSize(bcList->next);
  }
  return 0;
}

void populateCPool(JSContext *ctx, int offset, BCLList *bcList, JSValue *cpool)
{
  if (bcList)
  {
    if (bcList->hasPoolData)
    {
      // fprintf(stdout, "Adding to cpool at offset %d\n", offset);
      *(cpool + offset) = JS_DupValue(ctx, bcList->poolData);
      bcList->data.four = offset++;
    }
    return populateCPool(ctx, offset, bcList->next, cpool);
  }
}

void populateLambdaPoolReferences(JSContext *ctx, BCLList *bcList, int poolOffset)
{
  if (bcList)
  {
    if (bcList->lambdaPoolReference)
    {
      if (bcList->valueSize == 1)
      {
        int targetOffset = poolOffset + (bcList->data.one);
        // fprintf(stdout, "Patching lambda offset %d to %d\n", bcList->data.one, targetOffset);
        bcList->data.one = targetOffset;
      }
      else if (bcList->valueSize == 2)
      {
        int targetOffset = poolOffset + (bcList->data.two);
        // fprintf(stdout, "Patching lambda offset %d to %d\n", bcList->data.two, targetOffset);
        bcList->data.two = targetOffset;
      }
      else if (bcList->valueSize == 4)
      {
        int targetOffset = poolOffset + (bcList->data.four);
        // fprintf(stdout, "Patching lambda offset %d to %d\n", bcList->data.four, targetOffset);
        bcList->data.four = targetOffset;
      }
      else
      {
        fprintf(stderr, "Failed to patch lambda pool reference, no offset specified");
        exit(1);
      }
    }
    return populateLambdaPoolReferences(ctx, bcList->next, poolOffset);
  }
}

int findOffset(BCLList *bcList, int offset, int targetOffset)
{
  if (bcList)
  {
    if (bcList->isLabel && bcList->label == targetOffset)
    {
      // return offset + short_opcode_info(bcList->bc).size - 1;
      return offset - 1;
    }
    else
    {
      return findOffset(bcList->next, offset + short_opcode_info(bcList->bc).size, targetOffset);
    }
  }
  fprintf(stderr, "Failed to find BC offset for %d\n", targetOffset);
  exit(1);
}

void patchGotos(BCLList *bcList, int currOffset, BCLList *startBcList)
{
  if (bcList)
  {
    if (bcList->bc == OP_goto || bcList->bc == OP_catch || bcList->bc == OP_gosub)
    {
      uint32_t iriOffset = bcList->data.four;
      int actualOffset = findOffset(startBcList, 0, iriOffset);
      // fprintf(stdout, "Patching offset %d to %d\n", iriOffset, actualOffset);
      bcList->data.four = actualOffset - currOffset;
    }
    else if (bcList->bc == OP_if_true || bcList->bc == OP_if_false)
    {
      uint32_t iriOffset = bcList->data.four;
      int actualOffset = findOffset(startBcList, 0, iriOffset);
      // fprintf(stdout, "Patching (ifTrue) offset %d to %d\n", iriOffset, actualOffset);
      bcList->data.four = (actualOffset - currOffset);
    }
    patchGotos(bcList->next, currOffset + short_opcode_info(bcList->bc).size, startBcList);
  }
}

void freeBCLList(JSContext *ctx, BCLList *bcList)
{
  if (bcList)
  {
    freeBCLList(ctx, bcList->next);
    if (bcList->hasPoolData)
    {
      JS_FreeValue(ctx, bcList->poolData);
    }
    free(bcList);
  }
}

void populateBytecode(uint8_t *target, BCLList *currBC, int poolIDX)
{
  if (!currBC)
    return;
  if (currBC->hasPoolData)
  {
    currBC->data.four = poolIDX++;
    assert(currBC->valueSize == 4);
  }
  target[0] = currBC->bc;
  if (currBC->valueSize == 1)
  {
    uint8_t *t = (uint8_t *)(target + 1);
    *t = currBC->data.one;
  }
  else if (currBC->valueSize == 2)
  {
    uint16_t *t = (uint16_t *)(target + 1);
    *t = currBC->data.two;
  }
  else if (currBC->valueSize == 4)
  {
    uint32_t *t = (uint32_t *)(target + 1);
    *t = currBC->data.four;
  }

  if (currBC->hasFlags)
  {
    uint8_t *t = (uint8_t *)(target + short_opcode_info(currBC->bc).size - 1);
    *t = currBC->flags;
  }

  return populateBytecode(target + short_opcode_info(currBC->bc).size, currBC->next, poolIDX);
}

typedef struct StackSizeState
{
  int bc_len;
  int stack_len_max;
  uint16_t *stack_level_tab;
  int32_t *catch_pos_tab;
  int *pc_stack;
  int pc_stack_len;
  int pc_stack_size;
} StackSizeState;

int js_realloc_array(JSContext *ctx, void **parray,
                     int elem_size, int *psize, int req_size)
{
  int new_size;
  size_t slack;
  void *new_array;
  /* XXX: potential arithmetic overflow */
  new_size = max_int(req_size, *psize * 3 / 2);
  new_array = js_realloc2(ctx, *parray, new_size * elem_size, &slack);
  if (!new_array)
    return -1;
  new_size += slack / elem_size;
  *psize = new_size;
  *parray = new_array;
  return 0;
}

int js_resize_array(JSContext *ctx, void **parray, int elem_size,
                    int *psize, int req_size)
{
  if (unlikely(req_size > *psize))
    return js_realloc_array(ctx, parray, elem_size, psize, req_size);
  else
    return 0;
}

int ss_check(JSContext *ctx, StackSizeState *s,
             int pos, int op, int stack_len, int catch_pos)
{
  if ((unsigned)pos >= s->bc_len)
  {
    JS_ThrowInternalError(ctx, "bytecode buffer overflow (op=%d, pc=%d)", op, pos);
    return -1;
  }
  if (stack_len > s->stack_len_max)
  {
    s->stack_len_max = stack_len;
    if (s->stack_len_max > JS_STACK_SIZE_MAX)
    {
      JS_ThrowInternalError(ctx, "stack overflow (op=%d, pc=%d)", op, pos);
      return -1;
    }
  }
  if (s->stack_level_tab[pos] != 0xffff)
  {
    /* already explored: check that the stack size is consistent */
    if (s->stack_level_tab[pos] != stack_len)
    {
      JS_ThrowInternalError(ctx, "inconsistent stack size: %d %d (pc=%d)",
                            s->stack_level_tab[pos], stack_len, pos);
      return -1;
    }
    else if (s->catch_pos_tab[pos] != catch_pos)
    {
      JS_ThrowInternalError(ctx, "inconsistent catch position: %d %d (pc=%d)",
                            s->catch_pos_tab[pos], catch_pos, pos);
      return -1;
    }
    else
    {
      return 0;
    }
  }

  /* mark as explored and store the stack size */
  s->stack_level_tab[pos] = stack_len;
  s->catch_pos_tab[pos] = catch_pos;

  /* queue the new PC to explore */
  if (js_resize_array(ctx, (void **)&s->pc_stack, sizeof(s->pc_stack[0]),
                      &s->pc_stack_size, s->pc_stack_len + 1))
    return -1;
  s->pc_stack[s->pc_stack_len++] = pos;
  return 0;
}

int compute_stack_size(JSContext *ctx, uint8_t *bc_buf, int bcSize)
{
  StackSizeState s_s, *s = &s_s;
  int i, diff, n_pop, pos_next, stack_len, pos, op, catch_pos, catch_level;
  const JSOpCode *oi;
  s->bc_len = bcSize;
  /* bc_len > 0 */
  s->stack_level_tab = js_malloc(ctx, sizeof(s->stack_level_tab[0]) *
                                          s->bc_len);
  if (!s->stack_level_tab)
    return -1;
  for (i = 0; i < s->bc_len; i++)
    s->stack_level_tab[i] = 0xffff;
  s->pc_stack = NULL;
  s->catch_pos_tab = js_malloc(ctx, sizeof(s->catch_pos_tab[0]) * s->bc_len);
  if (!s->catch_pos_tab)
    goto fail;

  s->stack_len_max = 0;
  s->pc_stack_len = 0;
  s->pc_stack_size = 0;

  /* breadth-first graph exploration */
  if (ss_check(ctx, s, 0, OP_invalid, 0, -1))
    goto fail;

  while (s->pc_stack_len > 0)
  {
    pos = s->pc_stack[--s->pc_stack_len];
    stack_len = s->stack_level_tab[pos];
    catch_pos = s->catch_pos_tab[pos];
    op = bc_buf[pos];
    if (op == 0 || op >= OP_COUNT)
    {
      JS_ThrowInternalError(ctx, "invalid opcode (op=%d, pc=%d)", op, pos);
      goto fail;
    }
    oi = &short_opcode_info(op);
    // #ifdef ENABLE_DUMPS // JS_DUMP_BYTECODE_STACK
    //         if (check_dump_flag(ctx->rt, JS_DUMP_BYTECODE_STACK))
    // printf("%5d: %10s %5d %5d\n", pos, oi->name, stack_len, catch_pos);
    // #endif
    pos_next = pos + oi->size;
    if (pos_next > s->bc_len)
    {
      JS_ThrowInternalError(ctx, "bytecode buffer overflow (op=%d, pc=%d)", op, pos);
      goto fail;
    }
    n_pop = oi->n_pop;
    /* call pops a variable number of arguments */
    if (oi->fmt == OP_FMT_npop || oi->fmt == OP_FMT_npop_u16)
    {
      n_pop += get_u16(bc_buf + pos + 1);
    }
    else if (oi->fmt == OP_FMT_npopx)
    {
      n_pop += op - OP_call0;
    }

    if (stack_len < n_pop)
    {
      JS_ThrowInternalError(ctx, "stack underflow (op=%d, pc=%d)", op, pos);
      goto fail;
    }
    stack_len += oi->n_push - n_pop;
    if (stack_len > s->stack_len_max)
    {
      s->stack_len_max = stack_len;
      if (s->stack_len_max > JS_STACK_SIZE_MAX)
      {
        JS_ThrowInternalError(ctx, "stack overflow (op=%d, pc=%d)", op, pos);
        goto fail;
      }
    }
    switch (op)
    {
    case OP_tail_call:
    case OP_tail_call_method:
    case OP_return:
    case OP_return_undef:
    case OP_return_async:
    case OP_throw:
    case OP_throw_error:
    case OP_ret:
      goto done_insn;
    case OP_goto:
      diff = get_u32(bc_buf + pos + 1);
      pos_next = pos + 1 + diff;
      break;
    case OP_goto16:
      diff = (int16_t)get_u16(bc_buf + pos + 1);
      pos_next = pos + 1 + diff;
      break;
    case OP_goto8:
      diff = (int8_t)bc_buf[pos + 1];
      pos_next = pos + 1 + diff;
      break;
    case OP_if_true8:
    case OP_if_false8:
      diff = (int8_t)bc_buf[pos + 1];
      if (ss_check(ctx, s, pos + 1 + diff, op, stack_len, catch_pos))
        goto fail;
      break;
    case OP_if_true:
    case OP_if_false:
      diff = get_u32(bc_buf + pos + 1);
      if (ss_check(ctx, s, pos + 1 + diff, op, stack_len, catch_pos))
        goto fail;
      break;
    case OP_gosub:
      diff = get_u32(bc_buf + pos + 1);
      if (ss_check(ctx, s, pos + 1 + diff, op, stack_len + 1, catch_pos))
        goto fail;
      break;
    case OP_with_get_var:
    case OP_with_delete_var:
      diff = get_u32(bc_buf + pos + 5);
      if (ss_check(ctx, s, pos + 5 + diff, op, stack_len + 1, catch_pos))
        goto fail;
      break;
    case OP_with_make_ref:
    case OP_with_get_ref:
    case OP_with_get_ref_undef:
      diff = get_u32(bc_buf + pos + 5);
      if (ss_check(ctx, s, pos + 5 + diff, op, stack_len + 2, catch_pos))
        goto fail;
      break;
    case OP_with_put_var:
      diff = get_u32(bc_buf + pos + 5);
      if (ss_check(ctx, s, pos + 5 + diff, op, stack_len - 1, catch_pos))
        goto fail;
      break;
    case OP_catch:
      diff = get_u32(bc_buf + pos + 1);
      if (ss_check(ctx, s, pos + 1 + diff, op, stack_len, catch_pos))
        goto fail;
      catch_pos = pos;
      break;
    case OP_for_of_start:
    case OP_for_await_of_start:
      catch_pos = pos;
      break;
      /* we assume the catch offset entry is only removed with
         some op codes */
    case OP_drop:
      catch_level = stack_len;
      goto check_catch;
    case OP_nip:
      catch_level = stack_len - 1;
      goto check_catch;
    case OP_nip1:
      catch_level = stack_len - 1;
      goto check_catch;
    case OP_iterator_close:
      catch_level = stack_len + 2;
    check_catch:
      /* Note: for for_of_start/for_await_of_start we consider
         the catch offset is on the first stack entry instead of
         the thirst */
      if (catch_pos >= 0)
      {
        int level;
        level = s->stack_level_tab[catch_pos];
        if (bc_buf[catch_pos] != OP_catch)
          level++; /* for_of_start, for_wait_of_start */
        /* catch_level = stack_level before op_catch is executed ? */
        if (catch_level == level)
        {
          catch_pos = s->catch_pos_tab[catch_pos];
        }
      }
      break;
    case OP_nip_catch:
      if (catch_pos < 0)
      {
        JS_ThrowInternalError(ctx, "nip_catch: no catch op (pc=%d)", pos);
        goto fail;
      }
      stack_len = s->stack_level_tab[catch_pos];
      if (bc_buf[catch_pos] != OP_catch)
        stack_len++; /* for_of_start, for_wait_of_start */
      stack_len++;   /* no stack overflow is possible by construction */
      catch_pos = s->catch_pos_tab[catch_pos];
      break;
    default:
      break;
    }
    if (ss_check(ctx, s, pos_next, op, stack_len, catch_pos))
      goto fail;

  done_insn:;
  }
  js_free(ctx, s->pc_stack);
  js_free(ctx, s->catch_pos_tab);
  js_free(ctx, s->stack_level_tab);
  return s->stack_len_max;
fail:
  js_free(ctx, s->pc_stack);
  js_free(ctx, s->catch_pos_tab);
  js_free(ctx, s->stack_level_tab);
  return 0;
}

// ============== Helper Functions ============== //

void dumpBCLList(JSContext *ctx, BCLList *temp)
{
  int i = 0;
  while (temp)
  {
    fprintf(stdout, "BC[%d]: %s (size = %d bytes)", i, short_opcode_info(temp->bc).name, short_opcode_info(temp->bc).size);
    // assert(short_opcode_info(temp->bc).size == (temp->valueSize + 1));

    if (temp->bc == OP_push_const)
    {
      JSValue jsvalue = temp->poolData;
      fprintf(stdout, ", DATA_32: %d (\"%s\")\n", temp->data.four, JS_ToCString(ctx, jsvalue));
    }
    else if (temp->bc == OP_push_atom_value || temp->bc == OP_get_var || temp->bc == OP_get_field)
    {
      fprintf(stdout, ", StringData(%d): \"%s\"\n", temp->data.four, JS_AtomToCString(ctx, temp->data.four));
    }
    else if (temp->bc == OP_fclosure)
    {
      fprintf(stdout, ", DATA_32: %d (<Closure>)\n", temp->data.four);
    }
    else
    {
      switch (short_opcode_info(temp->bc).size)
      {
      case 2:
        fprintf(stdout, ", DATA_8: %d\n", temp->data.one);
        break;
      case 3:
        fprintf(stdout, ", DATA_16: %d\n", temp->data.two);
        break;
      case 5:
        fprintf(stdout, ", DATA_32: %d\n", temp->data.four);
        break;
      default:
        fprintf(stdout, "\n");
      }
    }
    i += short_opcode_info(temp->bc).size;
    temp = temp->next;
  }
}

JSValue generateQjsFunction(JSContext *ctx, IridiumSEXP *bbContainer, BCLList *startBC)
{
  bool isStrict = hasFlag(bbContainer, "STRICT");

  IridiumSEXP *bindingsSEXP = bbContainer->args[0];
  IridiumSEXP *localBindingsSEXP = bindingsSEXP->args[0];
  IridiumSEXP *remoteBindingsSEXP = bindingsSEXP->args[1];
  IridiumSEXP *lambdasSEXP = bindingsSEXP->args[2];

  // --- Setup ---
  int arg_count = 0;
  int var_count = 0;
  int closure_var_count = remoteBindingsSEXP->numArgs;
  int lambda_count = lambdasSEXP->numArgs;
  int bc_pool_count = getPoolSize(startBC);
  int cpool_count = bc_pool_count + lambda_count;
  int byte_code_len = getBCSize(startBC);

  // Initialize var/arg count
  for (int i = 0; i < localBindingsSEXP->numArgs; i++)
  {
    if (hasFlag(localBindingsSEXP->args[i], "JSARG") || hasFlag(localBindingsSEXP->args[i], "JSRESTARG"))
      arg_count++;
    else
      var_count++;
  }

  // Compute layout offsets
  int function_size = sizeof(JSFunctionBytecode);
  int cpool_offset = function_size;
  function_size += cpool_count * sizeof(JSValue);
  int vardefs_offset = function_size;
  function_size += (arg_count + var_count) * sizeof(JSVarDef);
  int closure_var_offset = function_size;
  function_size += closure_var_count * sizeof(JSClosureVar);
  int byte_code_offset = function_size;
  function_size += byte_code_len;

  // Allocate function object
  JSFunctionBytecode *b = js_mallocz(ctx, function_size);
  if (!b)
  {
    fprintf(stderr, "Failed to generate QJS function from Iridium code");
    exit(1);
  }

  b->header.ref_count = 1;
  b->header.gc_obj_type = JS_GC_OBJ_TYPE_FUNCTION_BYTECODE;

  // Allocate and initialize memory sections
  if (cpool_count > 0)
  {
    b->cpool = (JSValue *)((uint8_t *)b + cpool_offset);
    for (int i = 0; i < cpool_count; i++)
      b->cpool[i] = JS_UNDEFINED;
  }
  b->cpool_count = cpool_count;

  if (arg_count + var_count > 0)
  {
    b->vardefs = (JSVarDef *)((uint8_t *)b + vardefs_offset);
    b->arg_count = arg_count;
    b->var_count = var_count;
  }

  if (closure_var_count > 0)
  {
    b->closure_var = (JSClosureVar *)((uint8_t *)b + closure_var_offset);
    b->closure_var_count = closure_var_count;
  }

  b->byte_code_buf = (uint8_t *)b + byte_code_offset;
  b->byte_code_len = byte_code_len;

  // Set defined args count
  int ecmaArgsCount = getFlagNumber(bbContainer, "ECMAArgs");
  b->defined_arg_count = ecmaArgsCount;

  // Metadata
  b->func_name = JS_ATOM_NULL;
  b->filename = JS_ATOM_NULL;
  b->line_num = 1;
  b->col_num = 1;

  // Optional
  b->stack_size = 0;
  b->source = js_strdup(ctx, "<TestFunc>");
  b->source_len = strlen(b->source);
  b->pc2line_buf = NULL;
  b->pc2line_len = 0;

  // Function flags
  b->is_strict_mode = isStrict;
  b->has_prototype = 0;
  b->has_simple_parameter_list = 1;
  b->is_derived_class_constructor = 0;
  b->need_home_object = 0;
  b->func_kind = JS_FUNC_NORMAL;
  b->new_target_allowed = 0;
  b->super_call_allowed = 0;
  b->super_allowed = 0;
  b->arguments_allowed = 0;
  b->backtrace_barrier = 0;

  // Realm
  b->realm = JS_DupContext(ctx);

  // Populate Cpool
  populateCPool(ctx, 0, startBC, b->cpool);
  populateLambdaPoolReferences(ctx, startBC, bc_pool_count);

  // Populate Bytecode and compute stack size
  populateBytecode(b->byte_code_buf, startBC, 0);
  b->stack_size = compute_stack_size(ctx, b->byte_code_buf, b->byte_code_len);

  // Initialize Args + Var Defs
  for (int i = 0; i < var_count; i++)
  {
    IridiumSEXP *envBinding = localBindingsSEXP->args[i];
    ensureTag(envBinding, "EnvBinding");

    int scope_level = getFlagNumber(envBinding, "Scope");
    int scope_next = getFlagNumber(envBinding, "ParentScope");
    char *name = getFlagString(envBinding, "NAME");

    b->vardefs[i].var_name = JS_NewAtom(ctx, name);
    b->vardefs[i].scope_level = scope_level;
    b->vardefs[i].scope_next = scope_next;
    b->vardefs[i].var_kind = JS_VAR_NORMAL;

    b->vardefs[i].is_const = 0;
    b->vardefs[i].is_lexical = 0;
    b->vardefs[i].is_captured = 0;
    b->vardefs[i].is_static_private = 0;

    if (hasFlag(envBinding, "JSARG") || hasFlag(envBinding, "JSRESTARG"))
    {
      // NONE
    }
    else if (hasFlag(envBinding, "JSLET") || hasFlag(envBinding, "JSVAR"))
    {
      // NONE
    }
    else if (hasFlag(envBinding, "JSCONST"))
    {
      b->vardefs[i].is_const = true;
    }
    else
    {
      fprintf(stderr, "Valid flag not found...");
      exit(1);
    }
  }

  // Initialize Closuer Var Defs
  for (int i = 0; i < closure_var_count; i++)
  {
    IridiumSEXP *remoteBinding = remoteBindingsSEXP->args[i];
    ensureTag(remoteBinding, "RemoteEnvBinding");

    IridiumSEXP *next = remoteBinding->args[0];
    int refIDX = getFlagNumber(next, "REFIDX");

    b->closure_var[i].is_local = true;

    while (isTag(next, "RemoteEnvBinding"))
    {
      b->closure_var[i].is_local = false;
      next = next->args[0];
    }

    ensureTag(next, "EnvBinding");
    IridiumSEXP *envBinding = next;
    char *name = getFlagString(envBinding, "NAME");

    b->closure_var[i].is_arg = false;
    b->closure_var[i].is_const = false;
    b->closure_var[i].is_lexical = false;
    b->closure_var[i].var_kind = JS_VAR_NORMAL;
    b->closure_var[i].var_idx = refIDX;
    b->closure_var[i].var_name = JS_NewAtom(ctx, name);

    if (hasFlag(envBinding, "JSARG") || hasFlag(envBinding, "JSRESTARG"))
    {
      b->closure_var[i].is_arg = true;
    }
    else if (hasFlag(envBinding, "JSLET") || hasFlag(envBinding, "JSVAR"))
    {
      // NONE
    }
    else if (hasFlag(envBinding, "JSCONST"))
    {
      b->closure_var[i].is_const = true;
    }
    else
    {
      fprintf(stderr, "Valid flag not found...");
      exit(1);
    }

    // If marked as namespace import
    if (hasFlag(remoteBinding, "NSIMPORT"))
    {
      b->closure_var[i].is_local = true;
      b->closure_var[i].is_arg = false;
      b->closure_var[i].is_const = true;
      b->closure_var[i].is_lexical = true;
      b->closure_var[i].var_kind = JS_VAR_NORMAL;
      b->closure_var[i].var_idx = refIDX;
      b->closure_var[i].var_name = JS_NewAtom(ctx, name);
    }
  }

  // Set fun kind
  if (hasFlag(bbContainer, "GENERATOR") && hasFlag(bbContainer, "ASYNC"))
  {
    b->func_kind = JS_FUNC_ASYNC_GENERATOR;
  }
  else if (hasFlag(bbContainer, "GENERATOR"))
  {
    b->func_kind = JS_FUNC_GENERATOR;
  }
  else if (hasFlag(bbContainer, "ASYNC"))
  {
    b->func_kind = JS_FUNC_ASYNC;
  }

  // Set special flags
  if (hasFlag(bbContainer, "ARGUMENTS"))
  {
    b->arguments_allowed = 1;
  }

  if (hasFlag(bbContainer, "PROTO"))
  {
    b->has_prototype = 1;
  }

  if (hasFlag(bbContainer, "NEW"))
  {
    b->new_target_allowed = 1;
  }

  if (hasFlag(bbContainer, "SCALL"))
  {
    b->super_call_allowed = 1;
  }

  if (hasFlag(bbContainer, "SOBJ"))
  {
    b->super_allowed = 1;
  }

  if (hasFlag(bbContainer, "HOME"))
  {
    b->need_home_object = 1;
  }

  if (hasFlag(bbContainer, "DERIVED"))
  {
    b->is_derived_class_constructor = 1;
  }

  // Register with GC
  add_gc_object(ctx->rt, &b->header, JS_GC_OBJ_TYPE_FUNCTION_BYTECODE);

  // Wrap into JSValue
  JSValue func_val = JS_MKPTR(JS_TAG_FUNCTION_BYTECODE, b);
  return func_val;
}

JSValue generateBytecode(JSContext *ctx, IridiumSEXP *node)
{
  IridiumSEXP *file = node;
  ensureTag(file, "File");

  // Entry 1: Module Requests
  // Entry 2: Static Imports
  // Entry 3: Static Exports
  // Entry 4: Static Star Exports
  uint8_t moduleMetaEntries = 4;
  uint16_t numModules = node->numArgs - moduleMetaEntries;

  // dumpIridiumSEXP(stdout, file, 0);

  JSValue *moduleList = malloc(numModules * sizeof(JSValue));
  int topLevelModuleIdx = -1;

  for (int i = 0; i < numModules; ++i)
  {
    IridiumSEXP *bbContainer = file->args[moduleMetaEntries + i];
    ensureTag(bbContainer, "BBContainer");

    bool isTopLevelModule = hasFlag(bbContainer, "TopLevel");

    if (isTopLevelModule)
    {
      topLevelModuleIdx = i;
    }

    BCLList *bcTarget = malloc(sizeof(BCLList));
    BCLList *startBC = bcTarget;

    bcTarget->next = NULL;
    bcTarget->bc = 0;
    bcTarget->hasPoolData = false;
    bcTarget->poolData = JS_UNINITIALIZED;
    bcTarget->data.four = 0;
    bcTarget->valueSize = 0;

    // BB list
    IridiumSEXP *bbList = bbContainer->args[1];

    // Module Body
    for (int idx = 0; idx < bbList->numArgs; idx++)
    {
      IridiumSEXP *bb = bbList->args[idx];
      ensureTag(bb, "BB");
      bcTarget = pushLabel(ctx, bcTarget, getFlagNumber(bb, "IDX"));
      for (int stmtIDX = 0; stmtIDX < bb->numArgs; stmtIDX++)
      {
        IridiumSEXP *currStmt = bb->args[stmtIDX];
        bcTarget = handleIriStmt(ctx, bcTarget, currStmt);
      }
    }

    // Patch GOTOs
    patchGotos(startBC->next, 0, startBC->next);

    JSValue res = generateQjsFunction(ctx, bbContainer, startBC->next);

    // // Dump generated bytecode
    // dumpBCLList(ctx, startBC->next);

    // Free BCLList
    freeBCLList(ctx, startBC);

    moduleList[i] = res;
  }

  assert(topLevelModuleIdx >= 0);

  // Fill CPool with closures
  for (int i = 0; i < numModules; i++)
  {
    IridiumSEXP *bbContainer = file->args[moduleMetaEntries + i];
    ensureTag(bbContainer, "BBContainer");

    IridiumSEXP *bindingsInfo = bbContainer->args[0];
    ensureTag(bindingsInfo, "Bindings");

    JSValue targetClosure = moduleList[i];
    JSFunctionBytecode *targetClosurePtr = (JSFunctionBytecode *)targetClosure.u.ptr;

    IridiumSEXP *lambdasList = bindingsInfo->args[2];

    int poolStartIdx = targetClosurePtr->cpool_count - lambdasList->numArgs;

    for (int j = 0; j < lambdasList->numArgs; j++)
    {
      IridiumSEXP *poolBinding = lambdasList->args[j];
      ensureTag(poolBinding, "PoolBinding");
      // StartBBIDX of Closure that is needed
      int targetStartBBIDX = getFlagNumber(poolBinding, "StartBBIDX");

      // Find the location of the target closure
      JSValue res;
      bool found = false;
      for (int k = 0; k < numModules; k++)
      {
        IridiumSEXP *bbContainer = file->args[moduleMetaEntries + k];
        ensureTag(bbContainer, "BBContainer");
        int closureStartBBIDX = getFlagNumber(bbContainer, "StartBBIDX");
        if (closureStartBBIDX == targetStartBBIDX)
        {
          res = moduleList[k];
          found = true;
        }
      }
      assert(found);

      // Patch cpool to point to this closures
      targetClosurePtr->cpool[poolStartIdx + j] = res;
    }
  }

  if (check_dump_flag(ctx, JS_DUMP_BYTECODE_FINAL)) {
    fprintf(stdout, "[Iridium] Dumping all non-topLevel module code\n");
  }
  
  for (int i = 0; i < numModules; i++)
  {
    if (i == topLevelModuleIdx)
      continue;
    JSValue funBC = moduleList[i];
    JSFunctionBytecode *b = (JSFunctionBytecode *)funBC.u.ptr;
    if (check_dump_flag(ctx, JS_DUMP_BYTECODE_FINAL)) {
      js_dump_function_bytecode(ctx, b);
    }
  }
  return moduleList[topLevelModuleIdx];
}

typedef struct IridiumLoadResult
{
  bool isModule;
  void *ptr;
} IridiumLoadResult;

IridiumLoadResult compile_iri_module(JSContext *ctx, cJSON *json)
{
  cJSON *code = cJSON_GetObjectItem(json, "iridium");

  if (!cJSON_IsArray(code))
  {
    fprintf(stderr, "Expected the iridium key to be an array...");
    exit(1);
  }

  IridiumSEXP *iridiumCode = parseIridiumSEXP(code);

  // Generate BC
  JSValue moduleFunVal = generateBytecode(ctx, iridiumCode);

  JSFunctionBytecode *b = (JSFunctionBytecode *)moduleFunVal.u.ptr;
  bool isModule = hasFlag(iridiumCode, "JSModule");

  if (!isModule)
  {
    if (check_dump_flag(ctx, JS_DUMP_BYTECODE_FINAL)) {
      js_dump_function_bytecode(ctx, b);
    }
    return ((IridiumLoadResult){false, b});
  }

  // Module mode code
  b->func_kind = JS_FUNC_ASYNC;

  // Execute the file
  cJSON *absoluteFilePath = cJSON_GetObjectItem(json, "absoluteFilePath");
  JSModuleDef *m = js_new_module_def(ctx, JS_NewAtom(ctx, cJSON_GetStringValue(absoluteFilePath)));

  // Bytecode container gets the filename
  b->filename = JS_NewAtom(ctx, cJSON_GetStringValue(absoluteFilePath));

  // Initialize Module
  IridiumSEXP *moduleRequests = iridiumCode->args[0];
  IridiumSEXP *staticImports = iridiumCode->args[1];
  IridiumSEXP *staticExports = iridiumCode->args[2];
  IridiumSEXP *starExports = iridiumCode->args[3];

  if (moduleRequests->numArgs > 0)
  {
    // 1. Create External Module Requests
    m->req_module_entries_count = moduleRequests->numArgs;
    m->req_module_entries_size = m->req_module_entries_count;
    m->req_module_entries = js_mallocz(ctx, sizeof(m->req_module_entries[0]) * m->req_module_entries_size);

    for (int r = 0; r < moduleRequests->numArgs; ++r)
    {
      IridiumSEXP *moduleRequest = moduleRequests->args[r];
      char *SOURCE = getFlagString(moduleRequest, "SOURCE");
      m->req_module_entries[r].module_name = JS_NewAtom(ctx, SOURCE);
    }
  }

  if (staticImports->numArgs > 0)
  {
    // 2. Link Static Import Targets
    m->import_entries_count = staticImports->numArgs;
    m->import_entries_size = m->import_entries_count;
    m->import_entries = js_mallocz(ctx, sizeof(m->import_entries[0]) * m->import_entries_size);

    for (int im = 0; im < staticImports->numArgs; ++im)
    {
      IridiumSEXP *staticImport = staticImports->args[im];

      // Req Module IDX
      int reqModuleIDX = getFlagNumber(staticImport, "REQIDX");

      // Target IDX
      IridiumSEXP *bindingTarget = staticImport->args[0];
      ensureTag(bindingTarget, "RemoteEnvBinding");
      int bindingTargetIDX = getFlagNumber(bindingTarget, "REFIDX");

      // Field
      IridiumSEXP *fieldToGet = staticImport->args[1];
      ensureTag(fieldToGet, "String");

      char *fieldName = getFlagString(fieldToGet, "IridiumPrimitive");

      m->import_entries[im].var_idx = bindingTargetIDX;
      m->import_entries[im].import_name = JS_NewAtom(ctx, fieldName);
      m->import_entries[im].req_module_idx = reqModuleIDX;

      if (!hasFlag(bindingTarget, "NSIMPORT"))
      {
        // This needs to be set to false if the import is not a namespace import, this is a mess!!
        b->closure_var[bindingTargetIDX].is_local = false; // <- This was the problem!!!!
      }
    }
  }

  if (staticExports->numArgs > 0)
  {
    // 3. Link Exports
    m->export_entries_count = staticExports->numArgs;
    m->export_entries_size = m->export_entries_count;
    m->export_entries = js_mallocz(ctx, sizeof(m->export_entries[0]) * m->export_entries_size);

    for (int ex = 0; ex < staticExports->numArgs; ++ex)
    {
      IridiumSEXP *staticExport = staticExports->args[ex];

      if (isTag(staticExport, "NamedReexport"))
      {
        // Module Request IDX
        int reqIdx = getFlagNumber(staticExport, "REQIDX");
        m->export_entries[ex].u.req_module_idx = reqIdx;
        m->export_entries[ex].export_type = JS_EXPORT_TYPE_INDIRECT;
        m->export_entries[ex].local_name = JS_NewAtom(ctx, "*");
        m->export_entries[ex].export_name = JS_NewAtom(ctx, getFlagString(staticExport, "EXPORTNAME"));
      }
      else
      {
        // Stack Ref IDX
        IridiumSEXP *bindingTarget = staticExport->args[0];
        ensureTag(bindingTarget, "RemoteEnvBinding");
        int bindingTargetIDX = getFlagNumber(bindingTarget, "REFIDX");

        m->export_entries[ex].u.local.var_idx = bindingTargetIDX;
        m->export_entries[ex].export_type = JS_EXPORT_TYPE_LOCAL;
        m->export_entries[ex].local_name = JS_NewAtom(ctx, getFlagString(staticExport, "LOCALNAME"));
        m->export_entries[ex].export_name = JS_NewAtom(ctx, getFlagString(staticExport, "EXPORTNAME"));
      }
    }
  }

  if (starExports->numArgs > 0)
  {
    // 4. Star Exports
    m->star_export_entries_count = starExports->numArgs;
    m->star_export_entries_size = m->star_export_entries_count;
    m->star_export_entries = js_mallocz(ctx, sizeof(m->star_export_entries[0]) * m->star_export_entries_size);

    for (int ex = 0; ex < starExports->numArgs; ++ex)
    {
      IridiumSEXP *starExport = starExports->args[ex];
      // Req IDX
      int reqIDX = getFlagNumber(starExport, "REQIDX");
      m->star_export_entries[ex].req_module_idx = reqIDX;
    }
  }

  if (check_dump_flag(ctx, JS_DUMP_BYTECODE_FINAL)) {
    fprintf(stdout, "[Iridium] Dumping compiled topLevel code\n");
    js_dump_function_bytecode(ctx, b);
  }

  m->func_obj = moduleFunVal;

  return ((IridiumLoadResult){true, m});
}

void eval_iri_file(JSContext *ctx, const char *filename)
{
  cJSON *json = load_json(filename);

  if (json == NULL)
  {
    printf("Failed to load JSON.\n");
    return;
  }

  IridiumLoadResult iriRes = compile_iri_module(ctx, json);
  if (iriRes.isModule)
  {
    JSValue moduleVal = JS_NewModuleValue(ctx, iriRes.ptr);

    JS_ResolveModule(ctx, moduleVal);
    JSValue res = JS_EvalFunction(ctx, moduleVal);
    JS_FreeValue(ctx, res);
  }
  else
  {
    JSValue func_val = JS_MKPTR(JS_TAG_FUNCTION_BYTECODE, iriRes.ptr);
    JSValue res = JS_EvalFunction(ctx, func_val);
    JS_FreeValue(ctx, res);
  }

  cJSON_Delete(json);
}

void eval_iri_pika(JSContext *ctx, const char *filename)
{
  cJSON *json = load_json(filename);

  if (json == NULL)
  {
    printf("Failed to load JSON.\n");
    return;
  }

  cJSON *pika = cJSON_GetObjectItem(json, "pika");

  if (!cJSON_IsArray(pika))
  {
    fprintf(stderr, "Invalid pika bundle...");
    exit(1);
  }

  IridiumLoadResult iriRes;

  int numModules = cJSON_GetArraySize(pika);

  for (int i = 0; i < numModules; i++)
  {
    cJSON *json = cJSON_GetArrayItem(pika, i);

    IridiumLoadResult r = compile_iri_module(ctx, json);

    if (i == 0)
    {
      iriRes = r;
      // = JS_NewModuleValue(ctx, iriRes.ptr);
    }
  }

  if (iriRes.isModule)
  {
    JSValue moduleVal = JS_NewModuleValue(ctx, iriRes.ptr);

    JS_ResolveModule(ctx, moduleVal);
    JSValue res = JS_EvalFunction(ctx, moduleVal);
    JS_FreeValue(ctx, res);
  }
  else
  {
    JSValue func_val = JS_MKPTR(JS_TAG_FUNCTION_BYTECODE, iriRes.ptr);
    JSValue res = JS_EvalFunction(ctx, func_val);
    JS_FreeValue(ctx, res);
  }

  cJSON_Delete(json);
}

// Some basic bit operations
void setBit(int bitIndex, int *value)
{
  *value |= (1 << bitIndex);
}

void clearBit(int bitIndex, int *value)
{
  *value &= ~(1 << bitIndex);
}

void toggleBit(int bitIndex, int *value)
{
  *value ^= (1 << bitIndex);
}

bool isBitSet(int bitIndex, int value)
{
  return (value & (1 << bitIndex)) != 0;
}

//
// Write verifier later...
//

// bool isFlagName(IridiumFlag *flag, const char *const name)
// {
//     return strcmp(flag->name, name) == 0;
// }

// IridiumSEXP *handleFileSEXP(cJSON *args, cJSON *flags)
// {
//     // Parsing
//     IridiumSEXP *node = parseNode("File", args, flags);

//     // Post-Assertions
//     IridiumFlag **temp = node->flags;
//     IridiumFlag *currFlag = NULL;
//     int it = 0;
//     bool hasJSScript = false;
//     bool hasJSModule = false;
//     while (true)
//     {
//         currFlag = temp[it++];
//         if (currFlag == NULL)
//             break;
//         if (isFlagName(currFlag, "JSScript")) hasJSScript = true;
//         if (isFlagName(currFlag, "JSModule")) hasJSModule = true;
//     }

//     if (it <= 1)
//     {
//         fprintf(stderr, "Expected at most on flag for a File, found %d\n", it);
//         exit(1);
//     }

//     if (hasJSScript && hasJSModule) {
//         fprintf(stderr, "Expected either of JSScript or JSModule");
//         exit(1);
//     }

//     if (!(hasJSScript && hasJSModule)) {
//         fprintf(stderr, "Found invalid flag, expected either of JSScript of JSModule");
//         exit(1);
//     }

//     return node;
// }

// IridiumSEXP *handleBB(cJSON *args, cJSON *flags)
// {
//     // Parsing
//     IridiumSEXP *node = parseNode("File", args, flags);

//     // Post-Assertions
//     IridiumFlag **temp = node->flags;
//     IridiumFlag *currFlag = NULL;
//     int it = 0;
//     while (true)
//     {
//         currFlag = temp[it++];
//         if (currFlag == NULL)
//             break;

//         if (!(isFlagName(currFlag, "JSScript") || isFlagName(currFlag, "JSModule")))
//         {
//             fprintf(stderr, "Invalid Flag %s for file\n", currFlag->name);
//             exit(1);
//         }
//     }

//     if (it <= 1)
//     {
//         fprintf(stderr, "Expected at most on flag for a File, found %d\n", it);
//         exit(1);
//     }

//     return node;
// }

// IridiumSEXP *handleEnvDeclare(cJSON *args, cJSON *flags)
// {
//     // Parsing
//     IridiumSEXP *node = parseNode("File", args, flags);

//     // Post-Assertions
//     IridiumFlag **temp = node->flags;
//     IridiumFlag *currFlag = NULL;
//     int it = 0;
//     while (true)
//     {
//         currFlag = temp[it++];
//         if (currFlag == NULL)
//             break;

//         if (!(isFlagName(currFlag, "JSScript") || isFlagName(currFlag, "JSModule")))
//         {
//             fprintf(stderr, "Invalid Flag %s for file\n", currFlag->name);
//             exit(1);
//         }
//     }

//     if (it <= 1)
//     {
//         fprintf(stderr, "Expected at most on flag for a File, found %d\n", it);
//         exit(1);
//     }

//     return node;
// }

// void hello_world_test(JSContext *ctx)
// {
//   JSRuntime *rt = ctx->rt;
//   JSAtom atom_console = JS_NewAtom(ctx, "console");
//   JSAtom atom_log = JS_NewAtom(ctx, "log");
//   JSAtom atom_hello_world = JS_NewAtom(ctx, "Hello World");
//   uint16_t callMethodStackSize = 1;

//   uint8_t bytecode[] = {
//       OP_push_this,
//       OP_if_false8,
//       2,
//       OP_return_undef,
//       OP_get_var,
//       0, 0, 0, 0, // 32 bytes for console atom 'console'
//       OP_get_field2,
//       0, 0, 0, 0, // 32 bytes for console atom 'log'
//       OP_push_atom_value,
//       0, 0, 0, 0, // 32 bytes for console atom 'Hello World'
//       OP_call_method,
//       0, 0,
//       OP_drop,
//       OP_undefined,
//       OP_return_async};

//   memcpy(bytecode + 5, &atom_console, 4 * sizeof(uint8_t));
//   memcpy(bytecode + 10, &atom_log, 4 * sizeof(uint8_t));
//   memcpy(bytecode + 15, &atom_hello_world, 4 * sizeof(uint8_t));
//   memcpy(bytecode + 20, &callMethodStackSize, 2 * sizeof(uint8_t));

//   int function_size = sizeof(JSFunctionBytecode);
//   int cpool_count = 0;
//   int var_count = 0;
//   int byte_code_len = sizeof(bytecode);

//   int cpool_offset = function_size;
//   function_size += sizeof(JSValue) * cpool_count;

//   int vardefs_offset = function_size;
//   function_size += sizeof(JSVarDef) * var_count;

//   int bytecode_offset = function_size;
//   function_size += byte_code_len;

//   JSFunctionBytecode *b = js_mallocz(ctx, function_size);
//   if (!b)
//     return;

//   b->header.ref_count = 1;
//   b->header.gc_obj_type = JS_GC_OBJ_TYPE_FUNCTION_BYTECODE;

//   b->cpool = (JSValue *)((uint8_t *)b + cpool_offset);
//   b->vardefs = (JSVarDef *)((uint8_t *)b + vardefs_offset);
//   b->byte_code_buf = (uint8_t *)b + bytecode_offset;

//   b->cpool_count = cpool_count;
//   b->var_count = var_count;
//   b->arg_count = 0;
//   b->defined_arg_count = 0;
//   b->stack_size = 8;
//   b->closure_var_count = 0;
//   b->byte_code_len = byte_code_len;
//   b->func_name = JS_ATOM_NULL;
//   b->has_prototype = 1;
//   b->has_simple_parameter_list = 1;
//   b->is_strict_mode = 1;
//   b->func_kind = JS_FUNC_NORMAL;
//   b->realm = JS_DupContext(ctx);

//   /* Copy bytecode */
//   memcpy(b->byte_code_buf, bytecode, byte_code_len);

//   /* Insert into GC */
//   add_gc_object(rt, &b->header, JS_GC_OBJ_TYPE_FUNCTION_BYTECODE);

//   // Evaluate
//   JSValue fun_obj = JS_MKPTR(JS_TAG_FUNCTION_BYTECODE, b);
//   JSModuleDef *m = js_new_module_def(ctx, JS_NewAtom(ctx, "<unnamed>"));
//   m->func_obj = fun_obj;

//   JSValue module_obj = JS_NewModuleValue(ctx, m);

//   JSValue retVal = JS_EvalFunction(ctx, module_obj);

//   JS_FreeValue(ctx, retVal);
//   JS_FreeValue(ctx, fun_obj);

//   return;
// }
