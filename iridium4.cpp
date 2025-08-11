#include <stdio.h>
#include <stdlib.h>
extern "C"
{
#include "cJSON.h"
#include "iridium.h"
#include "./quickjs_expose.h"
#include "./quickjs-opcode.h"
#include "./cutils.h"
}
#include <assert.h>
#include <ctype.h>
#include <memory>
#include <vector>
#include <iterator>
#include <unordered_set>
using namespace std;

#define check_dump_flag(ctx, flag) ((JS_GetDumpFlags(ctx->rt) & (flag + 0)) == (flag + 0))

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
  res->args = (IridiumSEXP **)malloc(argsNum * sizeof(IridiumSEXP **));
  for (int i = 0; i < argsNum; ++i)
  {
    res->args[i] = parseIridiumSEXP(cJSON_GetArrayItem(args, i));
  }
}

void populateFlags(IridiumSEXP *res, cJSON *flags)
{
  int flagsNum = res->numFlags = cJSON_GetArraySize(flags);
  res->flags = (IridiumFlag **)malloc(flagsNum * sizeof(IridiumSEXP **));
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

    // IridiumFlag *currFlag = malloc(sizeof(IridiumFlag));
    IridiumFlag *currFlag = new IridiumFlag; //@@
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
  // IridiumSEXP *res = malloc(sizeof(IridiumSEXP));
  IridiumSEXP *res = new IridiumSEXP; //@@
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
} BCInstruction;

// ============== Push OP ============== //
void pushLabel(JSContext *ctx, vector<BCInstruction> &instructions, int label)
{
  BCInstruction inst;
  inst.bc = OP_nop;
  inst.lambdaPoolReference = false;
  inst.hasPoolData = false;
  inst.poolData = JS_UNINITIALIZED;
  inst.isLabel = true;
  inst.label = label;
  inst.valueSize = 0;
  inst.data.four = 0;
  inst.hasFlags = false;
  inst.flags = 0;
  instructions.push_back(inst);
  return;
}

// void push8(JSContext *ctx, vector<BCInstruction> &instructions, uint8_t opcode)
// {
//   BCInstruction inst;
//   inst.bc = opcode;
//   inst.lambdaPoolReference = false;
//   inst.hasPoolData = false;
//   inst.poolData = JS_UNINITIALIZED;
//   inst.isLabel = false;
//   inst.label = 0;
//   inst.valueSize = 0;
//   inst.data.four = 0;
//   instructions.push_back(inst);
//   return;
// }

void pushOP(JSContext *ctx, vector<BCInstruction> &instructions, OPCodeEnum opcode)
{
  BCInstruction inst;
  inst.bc = opcode;
  inst.lambdaPoolReference = false;
  inst.hasPoolData = false;
  inst.poolData = JS_UNINITIALIZED;
  inst.isLabel = false;
  inst.label = 0;
  inst.valueSize = 0;
  inst.data.four = 0;
  inst.hasFlags = false;
  inst.flags = 0;
  instructions.push_back(inst);
  return;
}

void pushOPFlags(JSContext *ctx, vector<BCInstruction> &instructions, OPCodeEnum opcode, uint8_t flags)
{
  BCInstruction inst;
  inst.bc = opcode;
  inst.lambdaPoolReference = false;
  inst.hasPoolData = false;
  inst.poolData = JS_UNINITIALIZED;
  inst.isLabel = false;
  inst.label = 0;
  inst.valueSize = 0;
  inst.data.four = 0;
  inst.hasFlags = true;
  inst.flags = flags;
  instructions.push_back(inst);
  return;
}

void pushOP8(JSContext *ctx, vector<BCInstruction> &instructions, OPCodeEnum opcode, uint8_t data)
{
  BCInstruction inst;
  inst.bc = opcode;
  inst.lambdaPoolReference = false;
  inst.hasPoolData = false;
  inst.poolData = JS_UNINITIALIZED;
  inst.isLabel = false;
  inst.label = 0;
  inst.valueSize = 1;
  inst.data.one = data;
  inst.hasFlags = false;
  inst.flags = 0;
  inst.hasFlags = false;
  inst.flags = 0;
  instructions.push_back(inst);
  return;
}

void pushOP16(JSContext *ctx, vector<BCInstruction> &instructions, OPCodeEnum opcode, uint16_t data)
{
  BCInstruction inst;
  inst.bc = opcode;
  inst.lambdaPoolReference = false;
  inst.hasPoolData = false;
  inst.poolData = JS_UNINITIALIZED;
  inst.isLabel = false;
  inst.label = 0;
  inst.valueSize = 2;
  inst.data.two = data;
  inst.hasFlags = false;
  inst.flags = 0;
  instructions.push_back(inst);
  return;
}

void pushOP32(JSContext *ctx, vector<BCInstruction> &instructions, OPCodeEnum opcode, uint32_t data)
{
  BCInstruction inst;
  inst.bc = opcode;
  inst.lambdaPoolReference = false;
  inst.hasPoolData = false;
  inst.poolData = JS_UNINITIALIZED;
  inst.isLabel = false;
  inst.label = 0;
  inst.valueSize = 4;
  inst.data.four = data;
  inst.hasFlags = false;
  inst.flags = 0;
  instructions.push_back(inst);
  return;
}

void pushOP32Flags(JSContext *ctx, vector<BCInstruction> &instructions, OPCodeEnum opcode, uint32_t data, uint8_t flags)
{
  BCInstruction inst;
  inst.bc = opcode;
  inst.lambdaPoolReference = false;
  inst.hasPoolData = false;
  inst.poolData = JS_UNINITIALIZED;
  inst.isLabel = false;
  inst.label = 0;
  inst.valueSize = 4;
  inst.data.four = data;
  inst.hasFlags = true;
  inst.flags = flags;
  instructions.push_back(inst);
  return;
}

void pushOPConst(JSContext *ctx, vector<BCInstruction> &instructions, OPCodeEnum opcode, JSValue cData)
{
  BCInstruction inst;
  inst.bc = opcode;
  inst.lambdaPoolReference = false;
  inst.hasPoolData = true;
  inst.poolData = cData;
  inst.isLabel = false;
  inst.label = 0;
  inst.valueSize = 4;
  inst.data.four = 0;
  inst.hasFlags = false;
  inst.flags = 0;
  instructions.push_back(inst);
  return;
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

bool hasFlag(IridiumSEXP *node, const char *flagToCheck)
{
  for (int i = 0; i < node->numFlags; i++)
  {
    IridiumFlag *flag = node->flags[i];
    if (strcmp(flag->name, flagToCheck) == 0)
      return true;
  }
  return false;
}

void ensureFlag(IridiumSEXP *node, const char *flag)
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

int getFlagNumber(IridiumSEXP *binding, const char *flagName)
{
  IridiumFlag *flag = getFlag(binding, flagName);
  if (flag->datatype == NUMBER)
  {
    return flag->value.number;
  }
  fprintf(stderr, "TODO: failed to get NUMBER\n");
  exit(1);
}

double getFlagDouble(IridiumSEXP *binding, const char *flagName)
{
  IridiumFlag *flag = getFlag(binding, flagName);
  if (flag->datatype == NUMBER)
  {
    return flag->value.number;
  }
  fprintf(stderr, "TODO: failed to get NUMBER(double)\n");
  exit(1);
}

char *getFlagString(IridiumSEXP *binding, const char *flagName)
{
  IridiumFlag *flag = getFlag(binding, flagName);
  if (flag->datatype == STRING)
  {
    return flag->value.string;
  }
  fprintf(stderr, "TODO: failed to get STRING\n");
  exit(1);
}

bool getFlagBoolean(IridiumSEXP *binding, const char *flagName)
{
  IridiumFlag *flag = getFlag(binding, flagName);
  if (flag->datatype == BOOLEAN)
  {
    return flag->value.boolean;
  }
  fprintf(stderr, "TODO: failed to get BOOLEAN\n");
  exit(1);
}

int getFlagNull(IridiumSEXP *binding, const char *flagName)
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

void handleEnvWrite(JSContext *ctx, vector<BCInstruction> &instructions, IridiumSEXP *currStmt, bool saveResToStack);

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

void storeWhatevesOnTheStack(JSContext *ctx, IridiumSEXP *loc, vector<BCInstruction> &instructions, bool safe, bool thisInit, bool isStrict, bool saveResToStack)
{
  if (saveResToStack)
    pushOP(ctx, instructions, OP_dup);

  // is lval global?
  if (isTag(loc, "GlobalBinding"))
  {
    char *name = getFlagString(loc, "NAME");

    if (safe)
    {
      pushOP32(ctx, instructions, OP_put_var_init, JS_NewAtom(ctx, name));
    }
    else if (isStrict)
    {
      pushOP32(ctx, instructions, OP_check_var, JS_NewAtom(ctx, name));
      pushOP(ctx, instructions, OP_swap);
      pushOP32(ctx, instructions, OP_put_var_strict, JS_NewAtom(ctx, name));
    }
    else
    {
      pushOP32(ctx, instructions, OP_put_var, JS_NewAtom(ctx, name));
    }
  }
  else
  {
    if (isTag(loc, "RemoteEnvBinding"))
    {
      int refIdx = getFlagNumber(loc, "REFIDX");
      pushOP16(ctx, instructions, thisInit ? OP_put_var_ref_check_init : safe ? OP_put_var_ref
                                                                              : OP_put_var_ref_check,
               refIdx);
    }
    else if (isTag(loc, "EnvBinding"))
    {
      int refIdx = getFlagNumber(loc, "REFIDX");
      pushOP16(ctx, instructions, thisInit ? OP_put_loc_check_init : safe ? OP_put_loc
                                                                          : OP_put_loc_check,
               refIdx);
    }
    else
    {
      fprintf(stderr, "TODO: store on stack, unhandled loc kind!!");
      exit(1);
    }
  }
  return;
}

// Gemini 2.5 pro, got it right, maybe...
void keepNDropM(JSContext *ctx, vector<BCInstruction> &instructions, int N, int M)
{
  // If M is zero or negative, no elements need to be dropped.
  if (M <= 0)
    return;

  // If N is negative, it's an invalid input. Do nothing.
  if (N < 0)
  {
    fprintf(stderr, "TODO: keepMDropN, invalid input !!");
    exit(1);
  }

  if (N == 2 && M == 1)
  {
    pushOP(ctx, instructions, OP_nip1);
    return;
  }
  fprintf(stderr, "TODO: keepMDropN, handle general case, validate code!!");
  exit(1);

  // Validate the logic for correctness first...
  // printf("Executing general path for N=%d, M=%d:\n", N, M);
  // // General case: Loop M times, each time dropping the element at depth N+1.
  // for (int i = 0; i < M; ++i)
  // {
  //   // The depth of the element to drop is always N+1 relative to the
  //   // block of N elements we are preserving.
  //   const int depth_to_drop = N + 1;

  //   switch (depth_to_drop)
  //   {
  //   case 1:
  //     // Keep 0, drop 1. This is a simple drop.
  //     currTarget = pushOP(ctx, currTarget, OP_drop);
  //     break;
  //   case 2:
  //     // Keep 1, drop 1. The element to drop is at depth 2.
  //     // This is what `nip` does.
  //     currTarget = pushOP(ctx, currTarget, OP_nip);
  //     break;
  //   case 3:
  //     // Keep 2, drop 1. The element to drop is at depth 3.
  //     // This is what `nip1` does.
  //     currTarget = pushOP(ctx, currTarget, OP_nip1);
  //     break;
  //   case 4:
  //     // Keep 3, drop 1. The element to drop is at depth 4.
  //     // We achieve this by moving the 4th element to the top (`rot4l`)
  //     // and then dropping it (`drop`).
  //     currTarget = pushOP(ctx, currTarget, OP_rot4l);
  //     currTarget = pushOP(ctx, currTarget, OP_drop);
  //     break;
  //   case 5:
  //     // Keep 4, drop 1. The element to drop is at depth 5.
  //     // We achieve this by moving the 5th element to the top (`rot5l`)
  //     // and then dropping it (`drop`).
  //     currTarget = pushOP(ctx, currTarget, OP_rot5l);
  //     currTarget = pushOP(ctx, currTarget, OP_drop);
  //     break;
  //   default:
  //     // The provided primitives do not support direct manipulation
  //     // of elements at depths greater than 5. Therefore, a general
  //     // solution for N > 4 is not possible with this instruction set.
  //     // In a real compiler, you might emit a call to a runtime
  //     // helper function or raise a compile-time error.
  //     fprintf(stderr, "Error: Cannot keepNDropM for N=%d. Operation not supported for depths > 5.\n", N);
  //     // Returning without emitting any more opcodes for this drop operation.
  //     break;
  //   }
  // }

  return;
}

void lowerToStack(JSContext *ctx, vector<BCInstruction> &instructions, IridiumSEXP *rval)
{
  if (isTag(rval, "JSForInStart"))
  {
    // Push obj onto the stack
    lowerToStack(ctx, instructions, rval->args[0]);

    // obj -> enum_obj
    return pushOP(ctx, instructions, OP_for_in_start);
  }
  else if (isTag(rval, "JSToObject"))
  {
    lowerToStack(ctx, instructions, rval->args[0]);
    return pushOP(ctx, instructions, OP_to_object);
  }
  if (isTag(rval, "String"))
  {
    char *data = getFlagString(rval, "IridiumPrimitive");
    JSAtom strAtom = JS_NewAtom(ctx, data);
    return pushOP32(ctx, instructions, OP_push_atom_value, strAtom);
  }
  else if (isTag(rval, "RegExp"))
  {
    char *exp = getFlagString(rval, "EXP");
    char *flags = getFlagString(rval, "FLAGS");

    JSValue expValue = JS_NewAtomString(ctx, exp);
    JSValue flagsValue = JS_NewAtomString(ctx, flags);

    pushOPConst(ctx, instructions, OP_push_const, expValue);

    // Compile regexp
    if (!ctx->compile_regexp)
    {
      fprintf(stderr, "RegExp compiler not found in the context");
      exit(1);
    }
    JSValue compiledRegexp = ctx->compile_regexp(ctx, expValue, flagsValue);
    pushOPConst(ctx, instructions, OP_push_const, compiledRegexp);
    return pushOP(ctx, instructions, OP_regexp);
  }
  else if (isTag(rval, "JSTemplate"))
  {
    pushOP(ctx, instructions, OP_push_empty_string);
    JSAtom fieldAtom = JS_NewAtom(ctx, "concat");
    pushOP32(ctx, instructions, OP_get_field2, fieldAtom);

    for (int i = 0; i < rval->numArgs; i++)
    {
      lowerToStack(ctx, instructions, rval->args[i]);
    }

    return pushOP16(ctx, instructions, OP_call_method, rval->numArgs);
  }
  else if (isTag(rval, "Number"))
  {
    int data = getFlagDouble(rval, "IridiumPrimitive");
    JSValue jsvalue = JS_NewNumber(ctx, data);
    return pushOPConst(ctx, instructions, OP_push_const, jsvalue);
  }
  else if (isTag(rval, "JSNUBD"))
  {
    return pushOPConst(ctx, instructions, OP_push_const, JS_UNINITIALIZED);
  }
  else if (isTag(rval, "RemoteEnvBinding"))
  {
    int refIDX = getFlagNumber(rval, "REFIDX");
    return pushOP16(ctx, instructions, OP_get_var_ref_check, refIDX);
  }
  else if (isTag(rval, "EnvBinding"))
  {
    // If this is an arg, get the arg idx
    if (hasFlag(rval, "JSARG"))
    {
      int argIdx = getFlagNumber(rval, "REFIDX");
      // int argIdx = parse_arg_index(getFlagString(rval->args[0], "IridiumPrimitive"));
      assert(argIdx > -1);
      return pushOP16(ctx, instructions, OP_get_arg, argIdx);
    }
    else if (hasFlag(rval, "JSRESTARG"))
    {
      int argIdx = getFlagNumber(rval, "REFIDX");
      // int argIdx = parse_arg_index(getFlagString(rval->args[0], "IridiumPrimitive"));
      assert(argIdx > -1);
      pushOP16(ctx, instructions, OP_rest, argIdx);
    }
    else
    {
      int refIDX = getFlagNumber(rval, "REFIDX");
      return pushOP16(ctx, instructions, OP_get_loc_check, refIDX);
    }
  }
  else if (isTag(rval, "GlobalBinding"))
  {
    char *lookupVal = getFlagString(rval, "NAME");
    if (strcmp(lookupVal, "undefined") == 0)
      return pushOP(ctx, instructions, OP_undefined);
    else
      return pushOP32(ctx, instructions, OP_get_var, JS_NewAtom(ctx, lookupVal));
  }
  else if (isTag(rval, "CallSite"))
  {
    int i = 0;

    // Handle Constructor Call Context, the class object is duplicated on the stack
    if (hasFlag(rval, "ConstructorCall"))
    {
      assert(rval->numArgs >= 1);
      lowerToStack(ctx, instructions, rval->args[0]);
      pushOP(ctx, instructions, OP_dup);
      i = 1;
    }

    // Private Call needs to be behind a brand check
    if (hasFlag(rval, "PrivateCall"))
    {
      assert(rval->numArgs >= 2);
      lowerToStack(ctx, instructions, rval->args[0]);
      lowerToStack(ctx, instructions, rval->args[1]);
      pushOP(ctx, instructions, OP_check_brand); // Ensure the function's home object's brand matches the brand of the current instance.
      i = 2;
    }

    // Lower Arguments
    for (; i < rval->numArgs; i++)
    {
      lowerToStack(ctx, instructions, rval->args[i]);
    }

    // Emit Call
    if (hasFlag(rval, "Super"))
    {
      return pushOP16(ctx, instructions, OP_call_constructor, rval->numArgs - 2);
    }
    else if (hasFlag(rval, "ConstructorCall"))
    {
      return pushOP16(ctx, instructions, OP_call_constructor, rval->numArgs - 1);
    }
    else if (hasFlag(rval, "CCall"))
    {
      return pushOP16(ctx, instructions, OP_call_method, rval->numArgs - 2);
    }
    else if (hasFlag(rval, "PrivateCall"))
    {
      return pushOP16(ctx, instructions, OP_call_method, rval->numArgs - 2);
    }
    else
    {
      return pushOP16(ctx, instructions, OP_call, rval->numArgs - 1);
    }
  }
  else if (isTag(rval, "EnvRead"))
  {
    return lowerToStack(ctx, instructions, rval->args[0]);
  }
  else if (isTag(rval, "EnvWrite"))
  {
    return handleEnvWrite(ctx, instructions, rval, true);
  }
  else if (isTag(rval, "Boolean"))
  {
    bool res = getFlagBoolean(rval, "IridiumPrimitive");
    if (res)
    {
      return pushOP(ctx, instructions, OP_push_true);
    }
    else
    {
      return pushOP(ctx, instructions, OP_push_false);
    }
  }
  else if (isTag(rval, "Unop"))
  {
    char *op = getFlagString(rval->args[0], "IridiumPrimitive");
    if (strcmp(op, "!") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      return pushOP(ctx, instructions, OP_lnot);
    }
    else if (strcmp(op, "-") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      return pushOP(ctx, instructions, OP_neg);
    }
    else if (strcmp(op, "+") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      return pushOP(ctx, instructions, OP_plus);
    }
    else if (strcmp(op, "~") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      return pushOP(ctx, instructions, OP_not);
    }
    else if (strcmp(op, "typeof") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      return pushOP(ctx, instructions, OP_typeof);
    }
    else if (strcmp(op, "delete") == 0)
    {
      IridiumSEXP *valToDelete = rval->args[1];
      assert(isTag(valToDelete, "List"));
      if (hasFlag(valToDelete, "UNOP_DEL_MEMBEREXPR"))
      {
        IridiumSEXP *receiver = valToDelete->args[0];
        IridiumSEXP *field = valToDelete->args[1];
        lowerToStack(ctx, instructions, receiver);
        lowerToStack(ctx, instructions, field);
        return pushOP(ctx, instructions, OP_delete);
      }
      else if (hasFlag(valToDelete, "UNOP_DEL_VAR"))
      {
        IridiumSEXP *var = valToDelete->args[0];
        assert(isTag(var, "String"));
        JSAtom varAtom = JS_NewAtom(ctx, getFlagString(var, "IridiumPrimitive"));
        return pushOP32(ctx, instructions, OP_delete_var, varAtom);
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
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_add);
    }
    else if (strcmp(op, "-") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_sub);
    }
    else if (strcmp(op, "/") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_div);
    }
    else if (strcmp(op, "%") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_mod);
    }
    else if (strcmp(op, "*") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_mul);
    }
    else if (strcmp(op, "**") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_pow);
    }
    else if (strcmp(op, "&") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_and);
    }
    else if (strcmp(op, "|") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_or);
    }
    else if (strcmp(op, ">>") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_sar);
    }
    else if (strcmp(op, ">>>") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_shr);
    }
    else if (strcmp(op, "<<") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_shl);
    }
    else if (strcmp(op, "^") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_xor);
    }
    else if (strcmp(op, "==") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_eq);
    }
    else if (strcmp(op, "===") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_strict_eq);
    }
    else if (strcmp(op, "!=") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_neq);
    }
    else if (strcmp(op, "!==") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_strict_neq);
    }
    else if (strcmp(op, "pin") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_private_in);
    }
    else if (strcmp(op, "in") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_in);
    }
    else if (strcmp(op, "instanceof") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_instanceof);
    }
    else if (strcmp(op, ">") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_gt);
    }
    else if (strcmp(op, "<") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_lt);
    }
    else if (strcmp(op, ">=") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_gte);
    }
    else if (strcmp(op, "<=") == 0)
    {
      lowerToStack(ctx, instructions, rval->args[1]);
      lowerToStack(ctx, instructions, rval->args[2]);
      return pushOP(ctx, instructions, OP_lte);
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
    lowerToStack(ctx, instructions, receiver);
    IridiumSEXP *field = rval->args[1];
    ensureTag(field, "String");
    JSAtom fieldAtom = JS_NewAtom(ctx, getFlagString(field, "IridiumPrimitive"));
    return pushOP32(ctx, instructions, OP_get_field, fieldAtom);
  }
  else if (isTag(rval, "JSComputedFieldRead"))
  {
    IridiumSEXP *receiver = rval->args[0];
    lowerToStack(ctx, instructions, receiver);
    IridiumSEXP *field = rval->args[1];
    lowerToStack(ctx, instructions, field);
    return pushOP(ctx, instructions, OP_get_array_el);
  }
  else if (isTag(rval, "JSObjectProp"))
  {
    IridiumSEXP *val = rval->args[1];
    lowerToStack(ctx, instructions, val);

    IridiumSEXP *field = rval->args[0];
    ensureTag(field, "String");
    JSAtom fieldAtom = JS_NewAtom(ctx, getFlagString(field, "IridiumPrimitive"));
    return pushOP32(ctx, instructions, OP_define_field, fieldAtom);
  }
  else if (isTag(rval, "JSComputedObjectProp"))
  {
    IridiumSEXP *field = rval->args[0];
    lowerToStack(ctx, instructions, field);

    IridiumSEXP *val = rval->args[1];
    lowerToStack(ctx, instructions, val);

    pushOP(ctx, instructions, OP_define_array_el);
    return pushOP(ctx, instructions, OP_drop);
  }

  // else if (isTag(rval, "JSObjectMethod"))
  // {
  //   IridiumSEXP *val = rval->args[1];
  //   lowerToStack(ctx, instructions, val);

  //   IridiumSEXP *field = rval->args[0];
  //   ensureTag(field, "String");
  //   JSAtom fieldAtom = JS_NewAtom(ctx, getFlagString(field, "IridiumPrimitive"));
  //   pushOP32(ctx, instructions, OP_define_method, fieldAtom);
  //   uint8_t op_flag;
  //   if (hasFlag(rval, "METHOD"))
  //   {
  //     op_flag = OP_DEFINE_METHOD_METHOD | OP_DEFINE_METHOD_ENUMERABLE;
  //   }
  //   else if (hasFlag(rval, "GET"))
  //   {
  //     op_flag = OP_DEFINE_METHOD_GETTER | OP_DEFINE_METHOD_ENUMERABLE;
  //   }
  //   else if (hasFlag(rval, "SET"))
  //   {
  //     op_flag = OP_DEFINE_METHOD_SETTER | OP_DEFINE_METHOD_ENUMERABLE;
  //   }
  //   else
  //   {
  //     fprintf(stderr, "TODO: JSObjectMethod invalid flag\n");
  //     exit(1);
  //   }
  //   return push8(ctx, instructions, op_flag);
  // }

  else if (isTag(rval, "JSObject"))
  {
    pushOP(ctx, instructions, OP_object);
    // for (int i = 0; i < rval->numArgs; i++)
    // {
    //   IridiumSEXP *ele = rval->args[i];
    //   if (isTag(ele, "JSObjectProp") || isTag(ele, "JSComputedObjectProp") || isTag(ele, "JSObjectMethod"))
    //   {
    //     lowerToStack(ctx, instructions, ele);
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
    pushOP32(ctx, instructions, OP_fclosure, poolOffset);
    instructions.back().lambdaPoolReference = true;
    return;
  }
  else if (isTag(rval, "JSClass"))
  {
    IridiumSEXP *className = rval->args[0];
    ensureTag(className, "String");
    JSAtom classNameAtom = JS_NewAtom(ctx, getFlagString(className, "IridiumPrimitive"));

    lowerToStack(ctx, instructions, rval->args[1]);

    // Instead of creating a closure, we push the constructor bytecode directly onto the stack
    {
      IridiumSEXP *constructorClosure = rval->args[2];
      uint32_t poolOffset = getFlagNumber(constructorClosure, "REFIDX");
      pushOP32(ctx, instructions, OP_push_const, poolOffset);
      instructions.back().lambdaPoolReference = true;
    }

    uint8_t flags = hasFlag(rval, "Derived") ? 1 : 0;
    pushOP32Flags(ctx, instructions, OP_define_class, classNameAtom, flags);
    // Class Flags, the bytecode itself is 5 + 1 bytes (1 byte OPcode + 4 byte name + 1 byte flags)

    // Set home object for classPropInitClosure
    IridiumSEXP *classPropInitClos = rval->args[3];
    lowerToStack(ctx, instructions, classPropInitClos);
    pushOP(ctx, instructions, OP_set_home_object);
    pushOP(ctx, instructions, OP_drop); // <- Drops the closure, not the prototype: set does not pop

    // Define methods on the prototype
    IridiumSEXP *methodList = rval->args[4];
    for (int i = 0; i < methodList->numArgs; ++i)
    {
      IridiumSEXP *methodName = methodList->args[i]->args[0];
      IridiumSEXP *methodLambda = methodList->args[i]->args[1];
      IridiumSEXP *methodKind = methodList->args[i]->args[2];
      assert(isTag(methodKind, "String"));
      char *kindStr = getFlagString(methodKind, "IridiumPrimitive");
      uint8_t op_flag;

      if (strcmp(kindStr, "METHOD") == 0)
      {
        op_flag = OP_DEFINE_METHOD_METHOD;
      }
      else if (strcmp(kindStr, "GET") == 0)
      {
        op_flag = OP_DEFINE_METHOD_GETTER;
      }
      else if (strcmp(kindStr, "SET") == 0)
      {
        op_flag = OP_DEFINE_METHOD_SETTER;
      }
      else
      {
        fprintf(stderr, "TODO: Classmethod flag is invalid\n");
        exit(1);
      }

      if (isTag(methodName, "String"))
      {
        // Lower the method on the stack
        lowerToStack(ctx, instructions, methodLambda);

        // Get the method name atom
        ensureTag(methodName, "String");
        JSAtom fieldAtom = JS_NewAtom(ctx, getFlagString(methodName, "IridiumPrimitive"));

        // Define method on the prototype
        pushOP32Flags(ctx, instructions, OP_define_method, fieldAtom, op_flag);
      }
      else if (isTag(methodName, "EnvRead"))
      {
        // Lower the computed name of the function on stack
        lowerToStack(ctx, instructions, methodName);

        // Lower the closure on the stack
        lowerToStack(ctx, instructions, methodLambda);

        // Define method on the prototype
        pushOPFlags(ctx, instructions, OP_define_method_computed, op_flag);
      }
      else if (isTag(methodName, "Private"))
      {
        // Get the lambda on the stack
        lowerToStack(ctx, instructions, methodLambda);

        // Set name
        JSAtom privateMethodNameAtom = JS_NewAtom(ctx, getFlagString(methodName, "IridiumPrimitive"));
        pushOP32(ctx, instructions, OP_set_name, privateMethodNameAtom);

        // Set home to be the prototype
        pushOP(ctx, instructions, OP_set_home_object); // sets the home to the prototype

        pushOP(ctx, instructions, OP_drop); // <- Drop the closure from stack
      }
    }

    // Define methods on the constructor
    pushOP(ctx, instructions, OP_swap); // ctr proto -> proto ctr
    IridiumSEXP *staticMethodList = rval->args[5];
    for (int i = 0; i < staticMethodList->numArgs; ++i)
    {
      IridiumSEXP *methodName = staticMethodList->args[i]->args[0];
      IridiumSEXP *methodLambda = staticMethodList->args[i]->args[1];
      IridiumSEXP *methodKind = staticMethodList->args[i]->args[2];
      assert(isTag(methodKind, "String"));
      char *kindStr = getFlagString(methodKind, "IridiumPrimitive");
      uint8_t op_flag;

      if (strcmp(kindStr, "METHOD") == 0)
      {
        op_flag = OP_DEFINE_METHOD_METHOD;
      }
      else if (strcmp(kindStr, "GET") == 0)
      {
        op_flag = OP_DEFINE_METHOD_GETTER;
      }
      else if (strcmp(kindStr, "SET") == 0)
      {
        op_flag = OP_DEFINE_METHOD_SETTER;
      }
      else
      {
        fprintf(stderr, "TODO: Classmethod flag is invalid\n");
        exit(1);
      }

      if (isTag(methodName, "String"))
      {
        // Lower the method on the stack
        lowerToStack(ctx, instructions, methodLambda);

        // Get the method name atom
        ensureTag(methodName, "String");
        JSAtom fieldAtom = JS_NewAtom(ctx, getFlagString(methodName, "IridiumPrimitive"));

        // Define method on the prototype
        pushOP32Flags(ctx, instructions, OP_define_method, fieldAtom, op_flag);
      }
      else if (isTag(methodName, "EnvRead"))
      {
        // Lower the computed name of the function on stack
        lowerToStack(ctx, instructions, methodName);

        // Lower the closure on the stack
        lowerToStack(ctx, instructions, methodLambda);

        // Define method on the prototype
        pushOPFlags(ctx, instructions, OP_define_method_computed, op_flag);
      }
      else if (isTag(methodName, "Private"))
      {
        // Get the lambda on the stack
        lowerToStack(ctx, instructions, methodLambda);

        // Set name
        JSAtom privateMethodNameAtom = JS_NewAtom(ctx, getFlagString(methodName, "IridiumPrimitive"));
        pushOP32(ctx, instructions, OP_set_name, privateMethodNameAtom);

        // Set home to be the prototype
        pushOP(ctx, instructions, OP_set_home_object); // sets the home to the prototype

        pushOP(ctx, instructions, OP_drop); // <- Drop the closure from stack
      }
    }
    pushOP(ctx, instructions, OP_swap); // proto ctr -> ctr proto

    // BrandPrototype
    if (hasFlag(rval, "BrandPrototype"))
    {
      pushOP(ctx, instructions, OP_dup);
      pushOP(ctx, instructions, OP_null);
      pushOP(ctx, instructions, OP_swap);
      pushOP(ctx, instructions, OP_add_brand);
    }

    pushOP(ctx, instructions, OP_drop);

    // BrandPrototype
    if (hasFlag(rval, "BrandConstructor"))
    {
      pushOP(ctx, instructions, OP_dup);
      pushOP(ctx, instructions, OP_dup);
      pushOP(ctx, instructions, OP_add_brand);
    }

    // Static Prop Init
    IridiumSEXP *staticPropInitClosure = rval->args[6];
    pushOP(ctx, instructions, OP_dup);
    lowerToStack(ctx, instructions, staticPropInitClosure);
    pushOP(ctx, instructions, OP_set_home_object);
    pushOP16(ctx, instructions, OP_call_method, 0);
    pushOP(ctx, instructions, OP_drop);

    return;
  }
  else if (isTag(rval, "JSArray"))
  {
    for (int i = 0; i < rval->numArgs; i++)
    {
      lowerToStack(ctx, instructions, rval->args[i]);
    }
    return pushOP16(ctx, instructions, OP_array_from, rval->numArgs);
  }
  else if (isTag(rval, "Private"))
  {
    char *data = getFlagString(rval, "IridiumPrimitive");
    JSAtom strAtom = JS_NewAtom(ctx, data);
    return pushOP32(ctx, instructions, OP_private_symbol, strAtom);
  }
  else if (isTag(rval, "JSPrivateFieldRead"))
  {
    lowerToStack(ctx, instructions, rval->args[0]);
    lowerToStack(ctx, instructions, rval->args[1]);
    return pushOP(ctx, instructions, OP_get_private_field);
  }
  else if (isTag(rval, "JSSuperFieldRead"))
  {
    lowerToStack(ctx, instructions, rval->args[0]);
    lowerToStack(ctx, instructions, rval->args[1]);
    lowerToStack(ctx, instructions, rval->args[2]);
    return pushOP(ctx, instructions, OP_get_super_value);
  }
  else if (isTag(rval, "JSSuperFieldWrite"))
  {
    lowerToStack(ctx, instructions, rval->args[0]);
    lowerToStack(ctx, instructions, rval->args[1]);
    lowerToStack(ctx, instructions, rval->args[2]);
    lowerToStack(ctx, instructions, rval->args[3]);
    return pushOP(ctx, instructions, OP_put_super_value);
  }
  else if (isTag(rval, "Null"))
  {
    return pushOP(ctx, instructions, OP_null);
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
    if (!r)
    {
      val = JS_ThrowOutOfMemory(ctx);
    }
    val = JS_CompactBigInt(ctx, r);
    return pushOPConst(ctx, instructions, OP_push_const, val);
  }
  // else if (isTag(rval, "Yield"))
  // {
  //   lowerToStack(ctx, instructions, rval->args[0]);
  //   return pushOP(ctx, instructions, OP_yield);
  // }
  else if (isTag(rval, "Await"))
  {
    lowerToStack(ctx, instructions, rval->args[0]);
    return pushOP(ctx, instructions, OP_await);
  }
  else if (isTag(rval, "Nope"))
  {
    return;
  }
  else if (isTag(rval, "FieldWrite"))
  {
    // Receiver
    IridiumSEXP *receiver = rval->args[0];
    lowerToStack(ctx, instructions, receiver);

    // Rval
    IridiumSEXP *valToPush = rval->args[2];
    lowerToStack(ctx, instructions, valToPush);
    pushOP(ctx, instructions, OP_dup);
    pushOP(ctx, instructions, OP_rot3r);

    // Field
    IridiumSEXP *field = rval->args[1];
    ensureTag(field, "String");
    JSAtom fieldAtom = JS_NewAtom(ctx, getFlagString(field, "IridiumPrimitive"));
    pushOP32(ctx, instructions, OP_put_field, fieldAtom);
  }
  else if (isTag(rval, "JSComputedFieldWrite"))
  {
    // Receiver
    IridiumSEXP *receiver = rval->args[0];
    lowerToStack(ctx, instructions, receiver);

    // Field
    IridiumSEXP *field = rval->args[1];
    lowerToStack(ctx, instructions, field);
    pushOP(ctx, instructions, OP_to_propkey);

    // Rval
    IridiumSEXP *assnVal = rval->args[2];
    lowerToStack(ctx, instructions, assnVal);

    // Receiver Field Rval -> Rval Receiver Field Rval
    pushOP(ctx, instructions, OP_insert3);

    pushOP(ctx, instructions, OP_put_array_el); // Receiver Field Rval
  }
  else if (isTag(rval, "JSADDBRAND"))
  {
    lowerToStack(ctx, instructions, rval->args[0]);
    lowerToStack(ctx, instructions, rval->args[1]);
    return pushOP(ctx, instructions, OP_add_brand);
  }
  else if (isTag(rval, "JSCheckConstructor"))
  {
    return pushOP(ctx, instructions, OP_check_ctor);
  }
  else if (isTag(rval, "StackPop"))
  {
    return;
  }
  else if (isTag(rval, "JSForInNext"))
  {
    lowerToStack(ctx, instructions, rval->args[0]);
    pushOP(ctx, instructions, OP_for_in_next);

    keepNDropM(ctx, instructions, 2, 1);

    return;
  }
  else if (isTag(rval, "JSForOfStart"))
  {
    // Push obj onto the stack
    lowerToStack(ctx, instructions, rval->args[0]);

    // obj -> enum_obj iterator_method catch_offset
    return pushOP(ctx, instructions, OP_for_of_start);
  }
  else if (isTag(rval, "JSForOfNext"))
  {
    // [it, meth, off] -> [it, meth, off, result, done]
    return pushOP16(ctx, instructions, OP_for_of_next, 0);
  }
  else if (isTag(rval, "JSForOfIteratorClose"))
  {
    return pushOP(ctx, instructions, OP_iterator_close);
  }
  else
  {
    fprintf(stderr, "TODO: unhandled RVal: %s\n", rval->tag);
    exit(1);
  }
  return;
}

// bool isSimpleAssignment(IridiumSEXP *currStmt)
// {
//   return currStmt->numArgs == 2 && (isTag(currStmt->args[0], "EnvBinding") || isTag(currStmt->args[0], "RemoteEnvBinding"));
// }

// void handleEnvWrite(JSContext *ctx, vector<BCInstruction> &instructions, IridiumSEXP *currStmt, bool saveResToStack)
// {
//   bool safe = getFlagBoolean(currStmt, "SAFE");
//   bool thisInit = getFlagBoolean(currStmt, "THISINIT");
//   // BINDING = VAL
//   if (isSimpleAssignment(currStmt))
//   {
//     IridiumSEXP *lval = currStmt->args[0];
//     IridiumSEXP *rval = currStmt->args[1];

//     // Lower RVal
//     if (isTag(rval, "EnvWrite"))
//     {
//       bool safe = getFlagBoolean(rval, "SAFE");
//       bool thisInit = getFlagBoolean(rval, "THISINIT");

//       IridiumSEXP *innerLVal = rval->args[0];
//       IridiumSEXP *innerRval = rval->args[1];
//       assert(!isTag(innerRval, "EnvWrite"));

//       // Lower and dup RVal
//       lowerToStack(ctx, instructions, innerRval);
//       pushOP(ctx, instructions, OP_dup);

//       // Inner LVal
//       if (thisInit)
//       {
//         // This init only happens for locals...
//         assert(isTag(innerLVal, "EnvBinding"));
//         int refIdx = getFlagNumber(innerLVal, "REFIDX");
//         pushOP16(ctx, instructions, OP_put_loc_check_init, refIdx);
//       }
//       else if (isTag(innerLVal, "RemoteEnvBinding"))
//       {
//         int refIdx = getFlagNumber(innerLVal, "REFIDX");
//         pushOP16(ctx, instructions, safe ? OP_put_var_ref : OP_put_var_ref_check, refIdx);
//       }
//       else if (isTag(innerLVal, "EnvBinding"))
//       {
//         int refIdx = getFlagNumber(innerLVal, "REFIDX");
//         pushOP16(ctx, instructions, safe ? OP_put_loc : OP_put_loc_check, refIdx);
//       }
//       else
//       {
//         fprintf(stderr, "TODO: Unhandled LVal kind!!");
//         exit(1);
//       }
//     }
//     else if (isTag(rval, "FieldWrite"))
//     {
//       // Receiver
//       IridiumSEXP *receiver = rval->args[0];
//       lowerToStack(ctx, instructions, receiver);

//       // Rval
//       IridiumSEXP *valToPush = rval->args[2];
//       lowerToStack(ctx, instructions, valToPush);
//       pushOP(ctx, instructions, OP_dup);
//       pushOP(ctx, instructions, OP_rot3r);

//       // Field
//       IridiumSEXP *field = rval->args[1];
//       ensureTag(field, "String");
//       JSAtom fieldAtom = JS_NewAtom(ctx, getFlagString(field, "IridiumPrimitive"));
//       pushOP32(ctx, instructions, OP_put_field, fieldAtom);
//     }

//     else if (isTag(rval, "JSComputedFieldWrite"))
//     {

//       IridiumSEXP *assnVal = rval->args[2];
//       lowerToStack(ctx, instructions, assnVal);

//       IridiumSEXP *receiver = rval->args[0];
//       lowerToStack(ctx, instructions, receiver);

//       IridiumSEXP *field = rval->args[1];
//       lowerToStack(ctx, instructions, field);
//       pushOP(ctx, instructions, OP_to_propkey);

//       lowerToStack(ctx, instructions, assnVal);

//       pushOP(ctx, instructions, OP_put_array_el); // obj prop val
//     }
//     else
//     {
//       // Lower RVal
//       lowerToStack(ctx, instructions, rval);
//     }

//     // Lower LVal
//     if (thisInit)
//     {
//       // This init only happens for locals...
//       assert(isTag(lval, "EnvBinding"));
//       int refIdx = getFlagNumber(lval, "REFIDX");
//       pushOP16(ctx, instructions, OP_put_loc_check_init, refIdx);
//     }
//     else if (isTag(lval, "RemoteEnvBinding"))
//     {
//       int refIdx = getFlagNumber(lval, "REFIDX");
//       pushOP16(ctx, instructions, safe ? OP_put_var_ref : OP_put_var_ref_check, refIdx);
//     }
//     else if (isTag(lval, "EnvBinding"))
//     {
//       int refIdx = getFlagNumber(lval, "REFIDX");
//       pushOP16(ctx, instructions, safe ? OP_put_loc : OP_put_loc_check, refIdx);
//     }
//     else
//     {
//       fprintf(stderr, "TODO: Unhandled LVal kind!!");
//       exit(1);
//     }
//   }
//   else
//   {
//     fprintf(stderr, "TODO: unhandled env write: %s\n", currStmt->tag);
//     exit(1);
//   }

//   return;
// }

void handleEnvWrite(JSContext *ctx, vector<BCInstruction> &instructions, IridiumSEXP *currStmt, bool saveResToStack)
{
  bool safe = getFlagBoolean(currStmt, "SAFE");
  bool thisInit = getFlagBoolean(currStmt, "THISINIT");
  bool isStrict = !hasFlag(currStmt, "SLOPPY");

  IridiumSEXP *loc = currStmt->args[0];
  IridiumSEXP *rval = currStmt->args[1];

  // Store something on the stack
  lowerToStack(ctx, instructions, rval);
  // Store that something where its required
  return storeWhatevesOnTheStack(ctx, loc, instructions, safe, thisInit, isStrict, saveResToStack);
}

void handleIriStmt(JSContext *ctx, vector<BCInstruction> &instructions, IridiumSEXP *currStmt)
{
  // printf("stmt_type=%s\n",currStmt->tag);
  if (isTag(currStmt, "EnvWrite"))
  {
    handleEnvWrite(ctx, instructions, currStmt, false);
  }
  else if (isTag(currStmt, "FieldWrite") || isTag(currStmt, "JSComputedFieldWrite")) // Make fast cases for these too...
  {
    lowerToStack(ctx, instructions, currStmt);
    return pushOP(ctx, instructions, OP_drop);
  }
  // else if (isTag(currStmt, "JSForInNext"))
  // {
  //   lowerToStack(ctx, instructions, currStmt->args[0]);
  //   pushOP(ctx, instructions, OP_for_in_next);

  //   IridiumSEXP *doneTarget = currStmt->args[1];
  //   assert(isTag(doneTarget, "EnvBinding"));
  //   int doneTargetIDX = getFlagNumber(doneTarget, "REFIDX");

  //   IridiumSEXP *nextValTarget = currStmt->args[2];
  //   assert(isTag(nextValTarget, "EnvBinding"));
  //   int nextValTargetIDX = getFlagNumber(nextValTarget, "REFIDX");

  //   pushOP16(ctx, instructions, OP_put_loc, doneTargetIDX);    // top of the stack contains <loop-done>
  //   pushOP16(ctx, instructions, OP_put_loc, nextValTargetIDX); // top - 1 of the stack contains <loop-next>
  //   return pushOP(ctx, instructions, OP_drop);                 // drop enum_obj
  // }
  // else if (isTag(currStmt, "JSForOfStart"))
  // {
  //   // Push obj onto the stack
  //   lowerToStack(ctx, instructions, currStmt->args[0]);

  //   // obj -> enum_obj iterator_method catch_offset
  //   return pushOP(ctx, instructions, OP_for_of_start);

  //   // pushOP(ctx, instructions, OP_swap);

  //   // IridiumSEXP *methodStackLocation = currStmt->args[1];
  //   // int methodStackLocationIDX = getFlagNumber(methodStackLocation, "REFIDX");
  //   // if (isTag(methodStackLocation, "EnvBinding")) {
  //   //   pushOP16(ctx, instructions, OP_put_loc_check, methodStackLocationIDX);
  //   // } else if (isTag(methodStackLocation, "RemoteEnvBinding")) {
  //   //   pushOP16(ctx, instructions, OP_put_var_ref_check, methodStackLocationIDX);
  //   // } else {
  //   //   fprintf(stderr, "TODO: Expected a EnvBinding or RemoteEnvBinding!!");
  //   // }

  //   // pushOP(ctx, instructions, OP_swap);

  //   // IridiumSEXP *methodItLocation = currStmt->args[2];
  //   // int methodItLocationIDX = getFlagNumber(methodItLocation, "REFIDX");
  //   // if (isTag(methodItLocation, "EnvBinding")) {
  //   //   pushOP16(ctx, instructions, OP_put_loc_check, methodItLocationIDX);
  //   // } else if (isTag(methodItLocation, "RemoteEnvBinding")) {
  //   //   pushOP16(ctx, instructions, OP_put_var_ref_check, methodItLocationIDX);
  //   // } else {
  //   //   fprintf(stderr, "TODO: Expected a EnvBinding or RemoteEnvBinding!!");
  //   // }
  // }
  // else if (isTag(currStmt, "JSForInStart"))
  // {
  //   // Push obj onto the stack
  //   lowerToStack(ctx, instructions, currStmt->args[0]);

  //   // obj -> enum_obj
  //   pushOP(ctx, instructions, OP_for_in_start);
  //   IridiumSEXP *stackLocation = currStmt->args[1];
  //   int stackLocationIDX = getFlagNumber(stackLocation, "REFIDX");
  //   if (isTag(stackLocation, "EnvBinding"))
  //   {
  //     pushOP16(ctx, instructions, OP_put_loc_check, stackLocationIDX);
  //   }
  //   else if (isTag(stackLocation, "RemoteEnvBinding"))
  //   {
  //     pushOP16(ctx, instructions, OP_put_var_ref_check, stackLocationIDX);
  //   }
  //   else
  //   {
  //     fprintf(stderr, "TODO: Expected a EnvBinding or RemoteEnvBinding!!");
  //   }
  // }
  // else if (isTag(currStmt, "JSForOfNext"))
  // {
  //   // [it, meth, off] -> [it, meth, off, result, done]
  //   pushOP16(ctx, instructions, OP_for_of_next, 0);

  //   // Store <for-of-loop-done> = done
  //   // Store <for-of-loop-next> = result
  //   assert(currStmt->numArgs == 2);
  //   for (int i = 0; i < currStmt->numArgs; i++)
  //   {
  //     IridiumSEXP *stackLocation = currStmt->args[i];
  //     int stackLocationIDX = getFlagNumber(stackLocation, "REFIDX");
  //     if (isTag(stackLocation, "EnvBinding"))
  //     {
  //       pushOP16(ctx, instructions, OP_put_loc_check, stackLocationIDX);
  //     }
  //     else if (isTag(stackLocation, "RemoteEnvBinding"))
  //     {
  //       pushOP16(ctx, instructions, OP_put_var_ref_check, stackLocationIDX);
  //     }
  //     else
  //     {
  //       fprintf(stderr, "TODO: Expected a EnvBinding or RemoteEnvBinding!!");
  //     }
  //   }
  // }
  // else if (isTag(currStmt, "JSADDBRAND"))
  // {
  //   lowerToStack(ctx, instructions, currStmt->args[0]);
  //   lowerToStack(ctx, instructions, currStmt->args[1]);
  //   return pushOP(ctx, instructions, OP_add_brand);
  // }
  // else if (isTag(currStmt, "JSComputedFieldWrite"))
  // {
  //   IridiumSEXP *receiver = currStmt->args[0];
  //   lowerToStack(ctx, instructions, receiver);

  //   IridiumSEXP *field = currStmt->args[1];
  //   lowerToStack(ctx, instructions, field);
  //   pushOP(ctx, instructions, OP_to_propkey);

  //   IridiumSEXP *assnVal = currStmt->args[2];
  //   lowerToStack(ctx, instructions, assnVal);

  //   return pushOP(ctx, instructions, OP_put_array_el); // obj prop val
  // }
  else if (isTag(currStmt, "StackRetain"))
  {
    if (currStmt->numArgs > 0)
    {
      for (int i = 0; i < currStmt->numArgs; i++)
      {
        lowerToStack(ctx, instructions, currStmt->args[i]);
      }
    }
    return;
  }
  else if (isTag(currStmt, "StackReject"))
  {
    if (currStmt->numArgs > 0)
    {
      for (int i = 0; i < currStmt->numArgs; i++)
      {
        lowerToStack(ctx, instructions, currStmt->args[i]);
      }
    }

    int nVal = getFlagNumber(currStmt, "NVAL");
    for (int i = 0; i < nVal; i++)
    {
      pushOP(ctx, instructions, OP_drop);
    }

    return;
  }
  else if (isTag(currStmt, "Throw"))
  {
    lowerToStack(ctx, instructions, currStmt->args[0]);
    return pushOP(ctx, instructions, OP_throw);
  }
  // else if (isTag(currStmt, "JSCheckConstructor"))
  // {
  //   return pushOP(ctx, instructions, OP_check_ctor);
  // }
  else if (isTag(currStmt, "JSCatchContext"))
  {
    IridiumSEXP *loc = currStmt->args[0];
    ensureTag(loc, "EnvBinding");
    int refIdx = getFlagNumber(loc, "REFIDX");
    return pushOP16(ctx, instructions, OP_put_loc, refIdx);
  }
  else if (isTag(currStmt, "PushForOfCatchContext"))
  {
    return lowerToStack(ctx, instructions, currStmt->args[0]);
  }
  else if (isTag(currStmt, "IfJump"))
  {
    // Push check to stack
    lowerToStack(ctx, instructions, currStmt->args[0]);

    bool isNot = hasFlag(currStmt, "NOT");

    // Jmp to TRUE if stack value is true
    pushOP32(ctx, instructions, isNot ? OP_if_false : OP_if_true, getFlagNumber(currStmt, "IDX"));

    return;
  }
  else if (isTag(currStmt, "IfElseJump"))
  {
    // Push check to stack
    lowerToStack(ctx, instructions, currStmt->args[0]);

    // Jmp to TRUE if stack value is true
    pushOP32(ctx, instructions, OP_if_true, getFlagNumber(currStmt, "TRUE"));

    // Jmp to FALSE if stack value is false
    pushOP32(ctx, instructions, OP_goto, getFlagNumber(currStmt, "FALSE"));

    return;
  }
  else if (isTag(currStmt, "JSModuleStart"))
  {
    pushOP(ctx, instructions, OP_push_this);
    pushOP8(ctx, instructions, OP_if_false8, 2);
    return pushOP(ctx, instructions, OP_return_undef);
  }
  else if (isTag(currStmt, "JSModuleEnd"))
  {
    pushOP(ctx, instructions, OP_undefined);
    return pushOP(ctx, instructions, OP_return_async);
  }
  else if (isTag(currStmt, "InvokeFinalizer"))
  {
    return pushOP32(ctx, instructions, OP_gosub, getFlagNumber(currStmt, "IDX"));
  }
  else if (isTag(currStmt, "Goto"))
  {
    return pushOP32(ctx, instructions, OP_goto, getFlagNumber(currStmt, "IDX"));
  }
  else if (isTag(currStmt, "PushCatchContext"))
  {
    return pushOP32(ctx, instructions, OP_catch, getFlagNumber(currStmt, "IDX"));
  }
  else if (isTag(currStmt, "PopCatchContext"))
  {
    return pushOP(ctx, instructions, OP_drop);
  }
  else if (isTag(currStmt, "Return"))
  {
    lowerToStack(ctx, instructions, currStmt->args[0]);
    return pushOP(ctx, instructions, OP_return);
  }
  else if (isTag(currStmt, "ReturnAsync"))
  {
    lowerToStack(ctx, instructions, currStmt->args[0]);
    return pushOP(ctx, instructions, OP_return_async);
  }
  else if (isTag(currStmt, "NOP"))
  {
    return;
  }
  // else if (isTag(currStmt, "JSTHISINIT"))
  // {
  //   pushOP(ctx, instructions, OP_push_this);
  //   IridiumSEXP *thisLoc = currStmt->args[0];
  //   ensureTag(thisLoc, "EnvBinding");
  //   int refIdx = getFlagNumber(thisLoc, "REFIDX");
  //   return pushOP16(ctx, instructions, OP_put_loc, refIdx);
  // }
  else if (isTag(currStmt, "JSImplicitBindingDeclaration"))
  {
    int OPID = getFlagNumber(currStmt, "OPID");
    bool safe = getFlagBoolean(currStmt, "SAFE");
    bool thisInit = getFlagBoolean(currStmt, "THISINIT");
    bool isStrict = !hasFlag(currStmt, "SLOPPY");
    switch (OPID)
    {
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    {
      pushOP8(ctx, instructions, OP_special_object, OPID);
      IridiumSEXP *loc = currStmt->args[0];
      storeWhatevesOnTheStack(ctx, loc, instructions, safe, thisInit, isStrict, false);
      break;
    }
    case 7:
    case 8:
    {
      IridiumSEXP *loc = currStmt->args[0];
      IridiumSEXP *args = currStmt->args[1];
      ensureTag(args, "List");
      assert(args->numArgs == 1);
      lowerToStack(ctx, instructions, args->args[0]);
      pushOP(ctx, instructions, OP_get_super);
      storeWhatevesOnTheStack(ctx, loc, instructions, safe, thisInit, isStrict, false);
      break;
    }
    case 9:
    {
      pushOP(ctx, instructions, OP_push_this);
      IridiumSEXP *loc = currStmt->args[0];
      storeWhatevesOnTheStack(ctx, loc, instructions, safe, thisInit, isStrict, false);
      break;
    }
    case 10:
    {
      pushOPConst(ctx, instructions, OP_push_const, JS_UNINITIALIZED);
      IridiumSEXP *loc = currStmt->args[0];
      storeWhatevesOnTheStack(ctx, loc, instructions, safe, thisInit, isStrict, false);
      break;
    }
    case 11:
    {
      pushOP(ctx, instructions, OP_undefined);
      IridiumSEXP *loc = currStmt->args[0];
      storeWhatevesOnTheStack(ctx, loc, instructions, safe, thisInit, isStrict, false);
      break;
    }
    default:
      fprintf(stderr, "TODO: OPID: %d for JSImplicitBindingDeclaration\n", OPID);
      exit(1);
      break;
    }
    return;
  }
  else if (isTag(currStmt, "JSMODULEMETAINIT"))
  {
    pushOP8(ctx, instructions, OP_special_object, 6);

    IridiumSEXP *thisLoc = currStmt->args[0];
    ensureTag(thisLoc, "EnvBinding");
    int refIdx = getFlagNumber(thisLoc, "REFIDX");

    return pushOP16(ctx, instructions, OP_put_loc, refIdx);
  }
  else if (isTag(currStmt, "JSARGUMENTSINIT"))
  {
    pushOP8(ctx, instructions, OP_special_object, 0);

    IridiumSEXP *argsLoc = currStmt->args[0];
    ensureTag(argsLoc, "EnvBinding");
    int refIdx = getFlagNumber(argsLoc, "REFIDX");

    return pushOP16(ctx, instructions, OP_put_loc, refIdx);
  }
  else if (isTag(currStmt, "JSMARGUMENTSINIT"))
  {
    pushOP8(ctx, instructions, OP_special_object, 1);

    IridiumSEXP *argsLoc = currStmt->args[0];
    ensureTag(argsLoc, "EnvBinding");
    int refIdx = getFlagNumber(argsLoc, "REFIDX");

    return pushOP16(ctx, instructions, OP_put_loc, refIdx);
  }
  // else if (isTag(currStmt, "CallSite"))
  // {
  //   lowerToStack(ctx, instructions, currStmt);
  //   return pushOP(ctx, instructions, OP_drop);
  // }
  else if (isTag(currStmt, "JSSUPEROBJINIT"))
  {
    pushOP8(ctx, instructions, OP_special_object, 4);
    pushOP(ctx, instructions, OP_get_super);
    IridiumSEXP *targetBinding = currStmt->args[0];
    ensureTag(targetBinding, "EnvBinding");
    int refIdx = getFlagNumber(targetBinding, "REFIDX");
    return pushOP16(ctx, instructions, OP_put_loc, refIdx);
  }
  else if (isTag(currStmt, "JSNEWTARGETINIT"))
  {
    pushOP8(ctx, instructions, OP_special_object, 3);
    IridiumSEXP *targetBinding = currStmt->args[0];
    ensureTag(targetBinding, "EnvBinding");
    int refIdx = getFlagNumber(targetBinding, "REFIDX");
    return pushOP16(ctx, instructions, OP_put_loc, refIdx);
  }
  else if (isTag(currStmt, "JSSUPERCTRINIT"))
  {
    pushOP8(ctx, instructions, OP_special_object, 2);
    pushOP(ctx, instructions, OP_get_super);
    IridiumSEXP *targetBinding = currStmt->args[0];
    ensureTag(targetBinding, "EnvBinding");
    int refIdx = getFlagNumber(targetBinding, "REFIDX");
    return pushOP16(ctx, instructions, OP_put_loc, refIdx);
  }
  // else if (isTag(currStmt, "JSHOMEOBJ"))
  // {
  //   pushOP8(ctx, instructions, OP_special_object, 4);
  //   IridiumSEXP *targetBinding = currStmt->args[0];
  //   ensureTag(targetBinding, "EnvBinding");
  //   int refIdx = getFlagNumber(targetBinding, "REFIDX");
  //   return pushOP16(ctx, instructions, OP_put_loc, refIdx);
  // }
  // else if (isTag(currStmt, "JSToObject"))
  // {
  //   lowerToStack(ctx, instructions, currStmt->args[0]);
  //   pushOP(ctx, instructions, OP_to_object);

  //   IridiumSEXP *stackLocation = currStmt->args[1];
  //   int stackLocationIDX = getFlagNumber(stackLocation, "REFIDX");
  //   if (isTag(stackLocation, "EnvBinding"))
  //   {
  //     pushOP16(ctx, instructions, OP_put_loc_check, stackLocationIDX);
  //   }
  //   else if (isTag(stackLocation, "RemoteEnvBinding"))
  //   {
  //     pushOP16(ctx, instructions, OP_put_var_ref_check, stackLocationIDX);
  //   }
  //   else
  //   {
  //     fprintf(stderr, "TODO: Expected a EnvBinding or RemoteEnvBinding!!");
  //   }
  // }
  else if (isTag(currStmt, "JSPrivateFieldWrite"))
  {
    lowerToStack(ctx, instructions, currStmt->args[0]);
    lowerToStack(ctx, instructions, currStmt->args[1]);
    lowerToStack(ctx, instructions, currStmt->args[2]);
    return pushOP(ctx, instructions, OP_define_private_field);
  }
  else if (isTag(currStmt, "JSInitialYield"))
  {
    return pushOP(ctx, instructions, OP_initial_yield);
  }
  // else if (isTag(currStmt, "JSClassMethodDefine"))
  // {
  //   IridiumSEXP *where = currStmt->args[0];
  //   lowerToStack(ctx, instructions, where);

  //   IridiumSEXP *what = currStmt->args[2];
  //   lowerToStack(ctx, instructions, what);

  //   IridiumSEXP *field = currStmt->args[1];
  //   ensureTag(field, "String");
  //   JSAtom fieldAtom = JS_NewAtom(ctx, getFlagString(field, "IridiumPrimitive"));
  //   pushOP32(ctx, instructions, OP_define_method, fieldAtom);
  //   uint8_t op_flag = OP_DEFINE_METHOD_METHOD | OP_DEFINE_METHOD_ENUMERABLE;
  //   return push8(ctx, instructions, op_flag);
  // }
  else if (isTag(currStmt, "JSCopyDataProperties"))
  {
    // exc_obj
    IridiumSEXP *exc_obj = currStmt->args[0];
    lowerToStack(ctx, instructions, exc_obj);

    // source
    IridiumSEXP *source = currStmt->args[1];
    lowerToStack(ctx, instructions, source);

    // target
    IridiumSEXP *target = currStmt->args[2];
    lowerToStack(ctx, instructions, target);

    // OP_copy_data_properties
    pushOP16(ctx, instructions, OP_copy_data_properties, 68);

    bool safe = getFlagBoolean(currStmt, "SAFE");
    bool thisInit = getFlagBoolean(currStmt, "THISINIT");
    bool isStrict = !hasFlag(currStmt, "SLOPPY");

    IridiumSEXP *loc = currStmt->args[3];
    storeWhatevesOnTheStack(ctx, loc, instructions, safe, thisInit, isStrict, false);

    pushOP(ctx, instructions, OP_drop);
    return pushOP(ctx, instructions, OP_drop);
  }
  // else if (isTag(currStmt, "JSIteratorClose"))
  // {
  //   return pushOP(ctx, instructions, OP_iterator_close);
  // }
  else if (isTag(currStmt, "Ret"))
  {
    return pushOP(ctx, instructions, OP_ret);
  }
  else if (isTag(currStmt, "Yield"))
  {
    lowerToStack(ctx, instructions, currStmt->args[0]);
    pushOP(ctx, instructions, OP_yield);

    IridiumSEXP *stackLocation = currStmt->args[1];
    int stackLocationIDX = getFlagNumber(stackLocation, "REFIDX");
    if (isTag(stackLocation, "EnvBinding"))
    {
      pushOP16(ctx, instructions, OP_put_loc_check, stackLocationIDX);
    }
    else if (isTag(stackLocation, "RemoteEnvBinding"))
    {
      pushOP16(ctx, instructions, OP_put_var_ref_check, stackLocationIDX);
    }
    else
    {
      fprintf(stderr, "YIELD: Expected a EnvBinding or RemoteEnvBinding!!");
    }

    stackLocation = currStmt->args[2];
    stackLocationIDX = getFlagNumber(stackLocation, "REFIDX");
    if (isTag(stackLocation, "EnvBinding"))
    {
      pushOP16(ctx, instructions, OP_put_loc_check, stackLocationIDX);
    }
    else if (isTag(stackLocation, "RemoteEnvBinding"))
    {
      pushOP16(ctx, instructions, OP_put_var_ref_check, stackLocationIDX);
    }
    else
    {
      fprintf(stderr, "YIELD: Expected a EnvBinding or RemoteEnvBinding!!");
    }
  }
  else if (isTag(currStmt, "JSSloppyDecl"))
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
      fprintf(stderr, "TODO: JSSloppyDecl invalid flag config\n");
      exit(1);
    }

    char *name = getFlagString(currStmt, "NAME");
    pushOP32Flags(ctx, instructions, OP_check_define_var, JS_NewAtom(ctx, name), check_flag);
    pushOP32Flags(ctx, instructions, OP_define_var, JS_NewAtom(ctx, name), define_flag);

    return;
  }
  else if (isTag(currStmt, "JSFuncDecl"))
  {
    IridiumSEXP *loc = currStmt->args[0];
    IridiumSEXP *closure = currStmt->args[1];

    if (isTag(loc, "GlobalBinding"))
    {
      char *name = getFlagString(loc, "NAME");
      pushOP32Flags(ctx, instructions, OP_check_define_var, JS_NewAtom(ctx, name), 64);
      lowerToStack(ctx, instructions, closure);
      pushOP32Flags(ctx, instructions, OP_define_func, JS_NewAtom(ctx, name), 0);
    }
    else
    {
      fprintf(stderr, "TODO: unhandled JSFuncDecl case, expected a GlobalBinding\n");
      exit(1);
    }
  }
  else if (isTag(currStmt, "JSAppend"))
  {
    lowerToStack(ctx, instructions, currStmt->args[0]); // tmp
    lowerToStack(ctx, instructions, currStmt->args[1]); // insertionIdx
    lowerToStack(ctx, instructions, currStmt->args[2]); // spreadVal
    pushOP(ctx, instructions, OP_append);

    bool safe = getFlagBoolean(currStmt, "SAFE");
    bool thisInit = getFlagBoolean(currStmt, "THISINIT");
    bool isStrict = !hasFlag(currStmt, "SLOPPY");

    { // InsertionIdxLoc
      IridiumSEXP *insertionLoc = currStmt->args[3];
      storeWhatevesOnTheStack(ctx, insertionLoc, instructions, safe, thisInit, isStrict, false);
    }

    { // tempLoc
      IridiumSEXP *tmpLoc = currStmt->args[4];
      storeWhatevesOnTheStack(ctx, tmpLoc, instructions, safe, thisInit, isStrict, false);
    }
  }
  else if (isTag(currStmt, "JSDefineObjProp"))
  {
    IridiumSEXP *obj = currStmt->args[0];
    lowerToStack(ctx, instructions, obj);
    IridiumSEXP *field = currStmt->args[1];
    IridiumSEXP *val = currStmt->args[2];

    if (isTag(field, "String"))
    {
      lowerToStack(ctx, instructions, val);
      JSAtom fieldAtom = JS_NewAtom(ctx, getFlagString(field, "IridiumPrimitive"));
      pushOP32(ctx, instructions, OP_define_field, fieldAtom);
    }
    else
    {
      lowerToStack(ctx, instructions, field);
      lowerToStack(ctx, instructions, val);
      pushOP(ctx, instructions, OP_define_array_el);
      pushOP(ctx, instructions, OP_drop);
    }

    bool safe = getFlagBoolean(currStmt, "SAFE");
    bool thisInit = getFlagBoolean(currStmt, "THISINIT");
    bool isStrict = !hasFlag(currStmt, "SLOPPY");

    { // tempLoc
      IridiumSEXP *loc = currStmt->args[3];
      storeWhatevesOnTheStack(ctx, loc, instructions, safe, thisInit, isStrict, false);
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

    IridiumSEXP *obj = currStmt->args[0];
    lowerToStack(ctx, instructions, obj);
    IridiumSEXP *field = currStmt->args[1];
    IridiumSEXP *val = currStmt->args[2];

    if (isTag(field, "String"))
    {
      lowerToStack(ctx, instructions, val);
      JSAtom fieldAtom = JS_NewAtom(ctx, getFlagString(field, "IridiumPrimitive"));
      pushOP32Flags(ctx, instructions, OP_define_method, fieldAtom, op_flag);
    }
    else
    {
      lowerToStack(ctx, instructions, field);
      lowerToStack(ctx, instructions, val);
      pushOPFlags(ctx, instructions, OP_define_method_computed, op_flag);
    }

    bool safe = getFlagBoolean(currStmt, "SAFE");
    bool thisInit = getFlagBoolean(currStmt, "THISINIT");
    bool isStrict = !hasFlag(currStmt, "SLOPPY");

    { // tempLoc
      IridiumSEXP *loc = currStmt->args[3];
      storeWhatevesOnTheStack(ctx, loc, instructions, safe, thisInit, isStrict, false);
    }
  }
  else
  {
    fprintf(stderr, "TODO: unhandled tag: %s\n", currStmt->tag);
    exit(1);
  }
  return;
}

void handleBB(JSContext *ctx, vector<BCInstruction> &instructions, IridiumSEXP *bb)
{
  ensureTag(bb, "BB");

  for (int stmtIDX = 0; stmtIDX < bb->numArgs; stmtIDX++)
  {
    IridiumSEXP *currStmt = bb->args[stmtIDX];
    handleIriStmt(ctx, instructions, currStmt);
  }
  return;
}

// ============== Code Generation ============== //

// ============== Helper Functions ============== //

int getPoolSize(const vector<BCInstruction> &instructions)
{
  int count = 0;
  for (size_t i = 1; i < instructions.size(); ++i)
  {
    auto &inst = instructions[i];
    if (inst.hasPoolData)
    {
      count++;
    }
  }
  return count;
}

int getBCSize(const vector<BCInstruction> &instructions)
{
  int count = 0;
  for (size_t i = 1; i < instructions.size(); ++i)
  {
    auto &inst = instructions[i];
    count += short_opcode_info(inst.bc).size;
  }
  return count;
}

void populateCPool(JSContext *ctx, vector<BCInstruction> &instructions, JSValue *cpool)
{
  int offset = 0;
  for (size_t i = 1; i < instructions.size(); ++i)
  {
    auto &inst = instructions[i];
    if (inst.hasPoolData)
    {
      // fprintf(stdout, "Adding to cpool at offset %d\n", offset);
      *(cpool + offset) = JS_DupValue(ctx, inst.poolData);
      inst.data.four = offset;
      offset++;
    }
  }
}

void populateLambdaPoolReferences(JSContext *ctx, vector<BCInstruction> &instructions, int poolOffset)
{
  for (size_t i = 1; i < instructions.size(); ++i)
  {
    auto &inst = instructions[i];
    if (inst.lambdaPoolReference)
    {
      if (inst.valueSize == 1)
      {
        int targetOffset = poolOffset + (inst.data.one);
        // fprintf(stdout, "Patching lambda offset %d to %d\n", inst.data.one, targetOffset);
        inst.data.one = targetOffset;
      }
      else if (inst.valueSize == 2)
      {
        int targetOffset = poolOffset + (inst.data.two);
        // fprintf(stdout, "Patching lambda offset %d to %d\n", inst.data.two, targetOffset);
        inst.data.two = targetOffset;
      }
      else if (inst.valueSize == 4)
      {
        int targetOffset = poolOffset + (inst.data.four);
        // fprintf(stdout, "Patching lambda offset %d to %d\n", inst.data.four, targetOffset);
        inst.data.four = targetOffset;
      }
      else
      {
        fprintf(stderr, "Failed to patch lambda pool reference, no offset specified");
        exit(1);
      }
    }
  }
}

int findOffset(vector<BCInstruction> &instructions, int targetOffset)
{
  int offset = 0;
  for (size_t i = 1; i < instructions.size(); ++i)
  {
    auto &inst = instructions[i];
    if (inst.isLabel && inst.label == targetOffset)
    {
      return offset + short_opcode_info(inst.bc).size - 1;
      // return offset-1;
    }
    else
    {
      offset += short_opcode_info(inst.bc).size;
    }
  }
  fprintf(stderr, "Failed to find BC offset for %d\n", targetOffset);
  exit(1);
}

void patchGotos(vector<BCInstruction> &instructions)
{
  int currOffset = 0;
  for (size_t i = 1; i < instructions.size(); ++i)
  {
    auto &inst = instructions[i];
    if (inst.bc == OP_goto || inst.bc == OP_catch || inst.bc == OP_gosub)
    {
      uint32_t iriOffset = inst.data.four;
      int actualOffset = findOffset(instructions, iriOffset);
      // fprintf(stdout, "Patching offset %d to %d\n", iriOffset, actualOffset);
      inst.data.four = actualOffset - currOffset;
    }
    else if (inst.bc == OP_if_true || inst.bc == OP_if_false)
    {
      uint32_t iriOffset = inst.data.four;
      int actualOffset = findOffset(instructions, iriOffset);
      // fprintf(stdout, "Patching (ifTrue) offset %d to %d\n", iriOffset, actualOffset);
      inst.data.four = actualOffset - currOffset;
    }
    currOffset += short_opcode_info(inst.bc).size;
  }
}

void freeBCLList(JSContext *ctx, vector<BCInstruction> &instructions)
{
  for (auto &inst : instructions)
  {
    if (inst.hasPoolData)
    {
      JS_FreeValue(ctx, inst.poolData);
    }
  }
  instructions.clear();
  instructions.shrink_to_fit();
}

void populateBytecode(uint8_t *target, const std::vector<BCInstruction> &instructions, size_t index, int &poolIDX)
{
  if (index >= instructions.size())
    return;

  const BCInstruction &currBC = instructions[index];

  if (currBC.hasPoolData)
  {
    // Note: This modifies poolIDX, but we can't modify the original data
    // You may need to handle pool data differently depending on your use case
    assert(currBC.valueSize == 4);
  }

  target[0] = currBC.bc;

  if (currBC.valueSize == 1)
  {
    uint8_t *t = (uint8_t *)(target + 1);
    *t = currBC.hasPoolData ? poolIDX++ : currBC.data.one;
  }
  else if (currBC.valueSize == 2)
  {
    uint16_t *t = (uint16_t *)(target + 1);
    *t = currBC.hasPoolData ? poolIDX++ : currBC.data.two;
  }
  else if (currBC.valueSize == 4)
  {
    uint32_t *t = (uint32_t *)(target + 1);
    *t = currBC.hasPoolData ? poolIDX++ : currBC.data.four;
  }

  // if (currBC.bc == OP_define_method || currBC.bc == OP_define_class)
  // {
  //   if (index + 1 < instructions.size())
  //   {
  //     uint8_t *t = (uint8_t *)(target + 5); // {0: OP} {atom: 1 2 3 4} {flag: 5}
  //     // Next slot is the op_flag
  //     *t = instructions[index + 1].bc;
  //     return populateBytecode(target + short_opcode_info(currBC.bc).size, instructions, index + 2, poolIDX);
  //   }
  //   return;
  // }

  // if (currBC.bc == OP_define_method_computed)
  // {
  //   if (index + 1 < instructions.size())
  //   {
  //     uint8_t *t = (uint8_t *)(target + 2); // {0: OP} {flag: 1}
  //     // Next slot is the op_flag
  //     *t = instructions[index + 1].bc;
  //     return populateBytecode(target + short_opcode_info(currBC.bc).size, instructions, index + 2, poolIDX);
  //   }
  //   return;
  // }

  if (currBC.hasFlags)
  {
    uint8_t *t = (uint8_t *)(target + short_opcode_info(currBC.bc).size - 1);
    *t = currBC.flags;
  }

  return populateBytecode(target + short_opcode_info(currBC.bc).size, instructions, index + 1, poolIDX);
}

// Alternative wrapper function to maintain similar interface
void populateBytecode(uint8_t *target, const std::vector<BCInstruction> &instructions, int poolIDX = 0)
{
  int mutablePoolIDX = poolIDX;
  populateBytecode(target, instructions, 1, mutablePoolIDX);
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
  s->stack_level_tab = (uint16_t *)js_malloc(ctx, sizeof(s->stack_level_tab[0]) *
                                                      s->bc_len);
  if (!s->stack_level_tab)
    return -1;
  for (i = 0; i < s->bc_len; i++)
    s->stack_level_tab[i] = 0xffff;
  s->pc_stack = NULL;
  s->catch_pos_tab = (int32_t *)js_malloc(ctx, sizeof(s->catch_pos_tab[0]) * s->bc_len);
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

void dumpBCLList(JSContext *ctx, vector<BCInstruction> &instructions)
{
  int i = 0;
  for (auto &inst : instructions)
  {
    fprintf(stdout, "BC[%d]: %s (size = %d bytes)", i, short_opcode_info(inst.bc).name, short_opcode_info(inst.bc).size);
    assert(short_opcode_info(inst.bc).size == (inst.valueSize + 1));

    if (inst.bc == OP_push_const)
    {
      JSValue jsvalue = inst.poolData;
      fprintf(stdout, ", DATA_32: %d (\"%s\")\n", inst.data.four, JS_ToCString(ctx, jsvalue));
    }
    else if (inst.bc == OP_push_atom_value || inst.bc == OP_get_var || inst.bc == OP_get_field)
    {
      fprintf(stdout, ", StringData(%d): \"%s\"\n", inst.data.four, JS_AtomToCString(ctx, inst.data.four));
    }
    else if (inst.bc == OP_fclosure)
    {
      fprintf(stdout, ", DATA_32: %d (<Closure>)\n", inst.data.four);
    }
    else
    {
      switch (short_opcode_info(inst.bc).size)
      {
      case 2:
        fprintf(stdout, ", DATA_8: %d\n", inst.data.one);
        break;
      case 3:
        fprintf(stdout, ", DATA_16: %d\n", inst.data.two);
        break;
      case 5:
        fprintf(stdout, ", DATA_32: %d\n", inst.data.four);
        break;
      default:
        fprintf(stdout, "\n");
      }
    }
    i += short_opcode_info(inst.bc).size;
  }
}

JSValue generateQjsFunction(JSContext *ctx, IridiumSEXP *bbContainer, vector<BCInstruction> &instructions)
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
  int bc_pool_count = getPoolSize(instructions);
  int cpool_count = bc_pool_count + lambda_count;
  int byte_code_len = getBCSize(instructions);

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
  JSFunctionBytecode *b = (JSFunctionBytecode *)js_mallocz(ctx, function_size);
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
    // b->defined_arg_count = 0;
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
  populateCPool(ctx, instructions, b->cpool);
  populateLambdaPoolReferences(ctx, instructions, bc_pool_count);
  // Populate Bytecode and compute stack size
  populateBytecode(b->byte_code_buf, instructions, 0);

  b->stack_size = compute_stack_size(ctx, b->byte_code_buf, b->byte_code_len);

  // Initialize Arg + Var Defs
  for (int i = 0; i < var_count; i++)
  {
    IridiumSEXP *envBinding = localBindingsSEXP->args[i];
    ensureTag(envBinding, "EnvBinding");

    // int refIDX = getFlagNumber(envBinding, "REFIDX");
    // assert(refIDX == i && "Local VarDef idx not found");
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
      // fprintf(stderr, "JSARG not expected...");
      // exit(1);
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

  // printf("ADDR: %p\n", b);

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

struct OffsetMapping
{
  int originalOffset;
  int newOffset;
  bool isNop;
  size_t instructionIndex;
};

// Build a mapping from old offsets to new offsets after NOP removal
std::vector<OffsetMapping> buildOffsetMapping(const std::vector<BCInstruction> &instructions)
{
  std::vector<OffsetMapping> mapping;
  int originalOffset = 0;
  int newOffset = 0;

  for (size_t i = 1; i < instructions.size(); ++i)
  {
    const auto &inst = instructions[i];
    OffsetMapping entry;
    entry.originalOffset = originalOffset;
    entry.newOffset = newOffset;
    entry.isNop = (inst.bc == OP_nop && inst.isLabel);
    entry.instructionIndex = i;

    mapping.push_back(entry);

    int instSize = short_opcode_info(inst.bc).size;
    originalOffset += instSize;

    // Only advance newOffset if this isn't a NOP we're removing
    if (!entry.isNop)
    {
      newOffset += instSize;
    }
  }

  return mapping;
}

// Find the new offset for a given original absolute offset
int findNewAbsoluteOffset(const std::vector<OffsetMapping> &mapping, int originalAbsoluteOffset)
{
  // Find the instruction at or just before the target offset
  for (size_t i = 0; i < mapping.size(); ++i)
  {
    if (mapping[i].originalOffset == originalAbsoluteOffset)
    {
      // If this is a NOP, find next non-NOP
      if (mapping[i].isNop)
      {
        for (size_t j = i + 1; j < mapping.size(); ++j)
        {
          if (!mapping[j].isNop)
          {
            return mapping[j].newOffset;
          }
        }
        // If no non-NOP found, this is likely end of function
        if (!mapping.empty())
        {
          return mapping.back().newOffset;
        }
      }
      return mapping[i].newOffset;
    }

    // If we've passed the target offset, use the previous instruction
    if (mapping[i].originalOffset > originalAbsoluteOffset && i > 0)
    {
      // Handle case where target is in the middle of an instruction
      return mapping[i - 1].newOffset + (originalAbsoluteOffset - mapping[i - 1].originalOffset);
    }
  }

  // If we're beyond all instructions, return the last offset
  if (!mapping.empty())
  {
    return mapping.back().newOffset + (originalAbsoluteOffset - mapping.back().originalOffset);
  }

  return originalAbsoluteOffset;
}

// Create a new instruction vector with NOPs removed and offsets patched
std::vector<BCInstruction> removeNOPs(JSContext *ctx, std::vector<BCInstruction> &instructions)
{
  // Build offset mapping
  std::vector<OffsetMapping> mapping = buildOffsetMapping(instructions);

  // Create new instruction vector
  std::vector<BCInstruction> newInstructions;

  // Keep the first dummy instruction
  if (!instructions.empty())
  {
    newInstructions.push_back(instructions[0]);
  }

  // Process each instruction
  int currentOriginalOffset = 0;
  int currentNewOffset = 0;

  for (size_t i = 1; i < instructions.size(); ++i)
  {
    const auto &inst = instructions[i];
    int instSize = short_opcode_info(inst.bc).size;

    // Skip NOPs that are just labels
    if (inst.bc == OP_nop && inst.isLabel)
    {
      currentOriginalOffset += instSize;
      continue;
    }

    // Copy the instruction
    BCInstruction newInst = inst;

    // Patch jump offsets (which are relative in QuickJS)
    bool needsPatching = false;
    int originalTargetAbsolute = 0;

    switch (inst.bc)
    {
    case OP_goto:
    case OP_catch:
    case OP_gosub:
      needsPatching = true;
      // Relative offset is from position after the opcode byte
      originalTargetAbsolute = currentOriginalOffset + 1 + (int32_t)inst.data.four;
      break;

    case OP_if_true:
    case OP_if_false:
      needsPatching = true;
      // Relative offset is from position after the opcode byte
      originalTargetAbsolute = currentOriginalOffset + 1 + (int32_t)inst.data.four;
      break;

    case OP_goto16:
      needsPatching = true;
      originalTargetAbsolute = currentOriginalOffset + 1 + (int16_t)inst.data.two;
      break;

    case OP_goto8:
    case OP_if_true8:
    case OP_if_false8:
      needsPatching = true;
      originalTargetAbsolute = currentOriginalOffset + 1 + (int8_t)inst.data.one;
      break;

    case OP_with_get_var:
    case OP_with_delete_var:
      needsPatching = true;
      // These have offset at bytes 5-8 (after atom)
      originalTargetAbsolute = currentOriginalOffset + 5 + (int32_t)inst.data.four;
      break;

    case OP_with_make_ref:
    case OP_with_get_ref:
    case OP_with_get_ref_undef:
    case OP_with_put_var:
      // Handle if these instructions are used
      break;
    }

    if (needsPatching)
    {
      int newTargetAbsolute = findNewAbsoluteOffset(mapping, originalTargetAbsolute);
      int newRelativeOffset = 0;

      // Calculate new relative offset based on instruction type
      switch (inst.bc)
      {
      case OP_goto:
      case OP_catch:
      case OP_gosub:
      case OP_if_true:
      case OP_if_false:
        // Offset is from position after opcode byte
        newRelativeOffset = newTargetAbsolute - (currentNewOffset + 1);
        newInst.data.four = (uint32_t)newRelativeOffset;
        break;

      case OP_goto16:
        newRelativeOffset = newTargetAbsolute - (currentNewOffset + 1);
        // Check if it still fits in 16 bits
        if (newRelativeOffset >= -32768 && newRelativeOffset <= 32767)
        {
          newInst.data.two = (uint16_t)newRelativeOffset;
        }
        else
        {
          // Would need to convert to 32-bit version
          fprintf(stderr, "Warning: 16-bit jump overflow after NOP removal\n");
          // For now, convert to OP_goto (32-bit)
          newInst.bc = OP_goto;
          newInst.valueSize = 4;
          newInst.data.four = (uint32_t)newRelativeOffset;
        }
        break;

      case OP_goto8:
        newRelativeOffset = newTargetAbsolute - (currentNewOffset + 1);
        // Check if it still fits in 8 bits
        if (newRelativeOffset >= -128 && newRelativeOffset <= 127)
        {
          newInst.data.one = (uint8_t)newRelativeOffset;
        }
        else if (newRelativeOffset >= -32768 && newRelativeOffset <= 32767)
        {
          // Convert to 16-bit version
          newInst.bc = OP_goto16;
          newInst.valueSize = 2;
          newInst.data.two = (uint16_t)newRelativeOffset;
        }
        else
        {
          // Convert to 32-bit version
          newInst.bc = OP_goto;
          newInst.valueSize = 4;
          newInst.data.four = (uint32_t)newRelativeOffset;
        }
        break;

      case OP_if_true8:
        newRelativeOffset = newTargetAbsolute - (currentNewOffset + 1);
        if (newRelativeOffset >= -128 && newRelativeOffset <= 127)
        {
          newInst.data.one = (uint8_t)newRelativeOffset;
        }
        else
        {
          // Convert to 32-bit version
          newInst.bc = OP_if_true;
          newInst.valueSize = 4;
          newInst.data.four = (uint32_t)newRelativeOffset;
        }
        break;

      case OP_if_false8:
        newRelativeOffset = newTargetAbsolute - (currentNewOffset + 1);
        if (newRelativeOffset >= -128 && newRelativeOffset <= 127)
        {
          newInst.data.one = (uint8_t)newRelativeOffset;
        }
        else
        {
          // Convert to 32-bit version
          newInst.bc = OP_if_false;
          newInst.valueSize = 4;
          newInst.data.four = (uint32_t)newRelativeOffset;
        }
        break;

      case OP_with_get_var:
      case OP_with_delete_var:
        // Offset is from position after the atom (5 bytes from start)
        newRelativeOffset = newTargetAbsolute - (currentNewOffset + 5);
        newInst.data.four = (uint32_t)newRelativeOffset;
        break;
      }
    }

    newInstructions.push_back(newInst);
    currentOriginalOffset += instSize;
    currentNewOffset += short_opcode_info(newInst.bc).size;
  }

  return newInstructions;
}

// Updated patchGotos function that works with the new NOP-removed instructions
void patchGotosAfterNOPRemoval(std::vector<BCInstruction> &instructions)
{
  int currOffset = 0;
  for (size_t i = 1; i < instructions.size(); ++i)
  {
    auto &inst = instructions[i];

    // These should already be patched by removeNOPs, but we need to handle
    // the original label-based jumps from handleIriStmt
    if (inst.bc == OP_goto || inst.bc == OP_catch || inst.bc == OP_gosub ||
        inst.bc == OP_if_true || inst.bc == OP_if_false ||
        inst.bc == OP_if_true8 || inst.bc == OP_if_false8)
    {

      // Find if this is still using the original Iridium label
      // The data.four/two/one field contains the target label at this point
      uint32_t iriLabel = inst.data.four;

      // Find the actual offset for this label
      int targetOffset = 0;
      bool found = false;
      int searchOffset = 0;

      for (size_t j = 1; j < instructions.size(); ++j)
      {
        if (instructions[j].isLabel && instructions[j].label == iriLabel)
        {
          targetOffset = searchOffset;
          found = true;
          break;
        }
        searchOffset += short_opcode_info(instructions[j].bc).size;
      }

      if (found)
      {
        // Update with relative offset
        int relativeOffset = targetOffset - currOffset;

        switch (inst.bc)
        {
        case OP_goto:
        case OP_catch:
        case OP_gosub:
        case OP_if_true:
        case OP_if_false:
          inst.data.four = relativeOffset;
          break;
        case OP_goto16:
          inst.data.two = (uint16_t)relativeOffset;
          break;
        case OP_goto8:
        case OP_if_true8:
        case OP_if_false8:
          inst.data.one = (uint8_t)relativeOffset;
          break;
        }
      }
    }

    currOffset += short_opcode_info(inst.bc).size;
  }
}

#include <algorithm>
#include <unordered_map>
#include <functional>

struct PeepholePattern
{
  std::vector<OPCodeEnum> pattern;
  std::function<bool(const std::vector<BCInstruction> &, size_t)> matcher;
  std::function<std::vector<BCInstruction>(const std::vector<BCInstruction> &, size_t)> replacer;
};

class PeepholeOptimizer
{
private:
  std::vector<PeepholePattern> patterns;

public:
  PeepholeOptimizer()
  {
    initializePatterns();
  }

  void initializePatterns()
  {
    // // Pattern 1: push_const + to_propkey -> push_const (when const is already a valid property key)
    // patterns.push_back({
    //     {OP_push_const, OP_to_propkey},
    //     [](const std::vector<BCInstruction>& instructions, size_t pos) {
    //         if (pos + 1 >= instructions.size()) return false;
    //         return instructions[pos].bc == OP_push_const &&
    //                instructions[pos + 1].bc == OP_to_propkey;
    //     },
    //     [](const std::vector<BCInstruction>& instructions, size_t pos) {
    //         // If the const is already a string or symbol, we can skip to_propkey
    //         std::vector<BCInstruction> result;
    //         result.push_back(instructions[pos]); // Keep push_const
    //         // Skip to_propkey
    //         return result;
    //     }
    // });

    // // Pattern 2: dup + drop -> nop (eliminate redundant operations)
    // patterns.push_back({
    //     {OP_dup, OP_drop},
    //     [](const std::vector<BCInstruction>& instructions, size_t pos) {
    //         if (pos + 1 >= instructions.size()) return false;
    //         return instructions[pos].bc == OP_dup &&
    //                instructions[pos + 1].bc == OP_drop;
    //     },
    //     [](const std::vector<BCInstruction>& instructions, size_t pos) {
    //         return std::vector<BCInstruction>(); // Remove both
    //     }
    // });

    // // Pattern 3: push_true/false + if_true/false -> goto (constant condition)
    // patterns.push_back({
    //     {OP_push_true, OP_if_true},
    //     [](const std::vector<BCInstruction>& instructions, size_t pos) {
    //         if (pos + 1 >= instructions.size()) return false;
    //         return instructions[pos].bc == OP_push_true &&
    //                instructions[pos + 1].bc == OP_if_true;
    //     },
    //     [](const std::vector<BCInstruction>& instructions, size_t pos) {
    //         std::vector<BCInstruction> result;
    //         BCInstruction gotoInst = instructions[pos + 1];
    //         gotoInst.bc = OP_goto;
    //         result.push_back(gotoInst);
    //         return result;
    //     }
    // });

    // // Pattern 4: push_false + if_true -> remove both (dead code)
    // patterns.push_back({
    //     {OP_push_false, OP_if_true},
    //     [](const std::vector<BCInstruction>& instructions, size_t pos) {
    //         if (pos + 1 >= instructions.size()) return false;
    //         return instructions[pos].bc == OP_push_false &&
    //                instructions[pos + 1].bc == OP_if_true;
    //     },
    //     [](const std::vector<BCInstruction>& instructions, size_t pos) {
    //         return std::vector<BCInstruction>(); // Remove both - branch never taken
    //     }
    // });

    // Pattern 5: Optimize small integer constants
    patterns.push_back({{OP_push_const},
                        [](const std::vector<BCInstruction> &instructions, size_t pos)
                        {
                          if (!instructions[pos].hasPoolData)
                            return false;
                          // Check if the constant is a small integer
                          JSValue val = instructions[pos].poolData;
                          if (JS_VALUE_GET_TAG(val) == JS_TAG_INT)
                          {
                            int32_t n = JS_VALUE_GET_INT(val);
                            return n >= -1 && n <= 5;
                          }
                          return false;
                        },
                        [](const std::vector<BCInstruction> &instructions, size_t pos)
                        {
                          std::vector<BCInstruction> result;
                          BCInstruction newInst;
                          JSValue val = instructions[pos].poolData;
                          int32_t n = JS_VALUE_GET_INT(val);

                          // Use specialized push instructions for small integers
                          switch (n)
                          {
                          case -1:
                            newInst.bc = OP_push_minus1;
                            break;
                          case 0:
                            newInst.bc = OP_push_0;
                            break;
                          case 1:
                            newInst.bc = OP_push_1;
                            break;
                          case 2:
                            newInst.bc = OP_push_2;
                            break;
                          case 3:
                            newInst.bc = OP_push_3;
                            break;
                          case 4:
                            newInst.bc = OP_push_4;
                            break;
                          case 5:
                            newInst.bc = OP_push_5;
                            break;
                          default:
                            return std::vector<BCInstruction>{instructions[pos]};
                          }

                          newInst.hasPoolData = false;
                          newInst.isLabel = false;
                          newInst.valueSize = 0;
                          newInst.data.four = 0;
                          result.push_back(newInst);
                          return result;
                        }});

    // // Pattern 6: goto to next instruction -> remove
    // patterns.push_back({
    //     {OP_goto},
    //     [](const std::vector<BCInstruction>& instructions, size_t pos) {
    //         if (instructions[pos].bc != OP_goto) return false;
    //         // Check if goto targets next instruction
    //         int32_t offset = (int32_t)instructions[pos].data.four;
    //         return offset == short_opcode_info(OP_goto).size - 1;
    //     },
    //     [](const std::vector<BCInstruction>& instructions, size_t pos) {
    //         return std::vector<BCInstruction>(); // Remove useless goto
    //     }
    // });

    // // Pattern 7: Optimize get_loc + put_loc of same variable (common in simple assignments)
    // patterns.push_back({
    //     {OP_get_loc_check, OP_put_loc},
    //     [](const std::vector<BCInstruction>& instructions, size_t pos) {
    //         if (pos + 1 >= instructions.size()) return false;
    //         return instructions[pos].bc == OP_get_loc_check &&
    //                instructions[pos + 1].bc == OP_put_loc &&
    //                instructions[pos].data.two == instructions[pos + 1].data.two;
    //     },
    //     [](const std::vector<BCInstruction>& instructions, size_t pos) {
    //         // This is a no-op (reading and writing same local)
    //         return std::vector<BCInstruction>();
    //     }
    // });

    // // Pattern 8: Optimize push_empty_string + get_field2 for concat
    // patterns.push_back({
    //     {OP_push_empty_string, OP_get_field2},
    //     [](const std::vector<BCInstruction>& instructions, size_t pos) {
    //         if (pos + 1 >= instructions.size()) return false;
    //         return instructions[pos].bc == OP_push_empty_string &&
    //                instructions[pos + 1].bc == OP_get_field2;
    //     },
    //     [](const std::vector<BCInstruction>& instructions, size_t pos) {
    //         // Keep as is but mark for potential string builder optimization
    //         return std::vector<BCInstruction>{instructions[pos], instructions[pos + 1]};
    //     }
    // });
  }

  std::vector<BCInstruction> optimize(const std::vector<BCInstruction> &instructions)
  {
    std::vector<BCInstruction> optimized;

    // Keep first dummy instruction
    if (!instructions.empty())
    {
      optimized.push_back(instructions[0]);
    }

    size_t i = 1;
    while (i < instructions.size())
    {
      bool matched = false;

      // Try each pattern
      for (const auto &pattern : patterns)
      {
        if (pattern.matcher(instructions, i))
        {
          auto replacement = pattern.replacer(instructions, i);
          optimized.insert(optimized.end(), replacement.begin(), replacement.end());
          i += pattern.pattern.size(); // Skip matched instructions
          matched = true;
          break;
        }
      }

      if (!matched)
      {
        optimized.push_back(instructions[i]);
        i++;
      }
    }

    return optimized;
  }
};

// Additional optimization: Jump threading
class JumpOptimizer
{
public:
  static void optimizeJumps(std::vector<BCInstruction> &instructions)
  {
    // Build jump target map
    std::unordered_map<int, int> jumpTargets;

    for (size_t i = 1; i < instructions.size(); ++i)
    {
      if (isJumpInstruction((OPCodeEnum)instructions[i].bc))
      {
        int target = getJumpTarget(instructions, i);

        // Follow jump chains
        int finalTarget = target;
        std::unordered_set<int> visited;

        while (visited.find(finalTarget) == visited.end())
        {
          visited.insert(finalTarget);

          // Find instruction at target
          size_t targetIdx = findInstructionAtOffset(instructions, finalTarget);
          if (targetIdx < instructions.size() &&
              instructions[targetIdx].bc == OP_goto)
          {
            finalTarget = getJumpTarget(instructions, targetIdx);
          }
          else
          {
            break;
          }
        }

        // Update jump target if we found a chain
        if (finalTarget != target)
        {
          updateJumpTarget(instructions, i, finalTarget);
        }
      }
    }

    // Optimize jump sizes (32-bit -> 16-bit -> 8-bit where possible)
    optimizeJumpSizes(instructions);
  }

private:
  static bool isJumpInstruction(OPCodeEnum op)
  {
    return op == OP_goto || op == OP_goto16 || op == OP_goto8 ||
           op == OP_if_true || op == OP_if_true8 ||
           op == OP_if_false || op == OP_if_false8 ||
           op == OP_catch || op == OP_gosub;
  }

  static int getJumpTarget(const std::vector<BCInstruction> &instructions, size_t idx)
  {
    const auto &inst = instructions[idx];
    int currentOffset = calculateOffset(instructions, idx);
    int relativeOffset = 0;

    switch (inst.bc)
    {
    case OP_goto:
    case OP_if_true:
    case OP_if_false:
    case OP_catch:
    case OP_gosub:
      relativeOffset = (int32_t)inst.data.four;
      break;
    case OP_goto16:
      relativeOffset = (int16_t)inst.data.two;
      break;
    case OP_goto8:
    case OP_if_true8:
    case OP_if_false8:
      relativeOffset = (int8_t)inst.data.one;
      break;
    }

    return currentOffset + 1 + relativeOffset;
  }

  static void updateJumpTarget(std::vector<BCInstruction> &instructions,
                               size_t idx, int newTarget)
  {
    auto &inst = instructions[idx];
    int currentOffset = calculateOffset(instructions, idx);
    int newRelativeOffset = newTarget - currentOffset - 1;

    switch (inst.bc)
    {
    case OP_goto:
    case OP_if_true:
    case OP_if_false:
    case OP_catch:
    case OP_gosub:
      inst.data.four = (uint32_t)newRelativeOffset;
      break;
    case OP_goto16:
      inst.data.two = (uint16_t)newRelativeOffset;
      break;
    case OP_goto8:
    case OP_if_true8:
    case OP_if_false8:
      inst.data.one = (uint8_t)newRelativeOffset;
      break;
    }
  }

  static size_t findInstructionAtOffset(const std::vector<BCInstruction> &instructions,
                                        int targetOffset)
  {
    int offset = 0;
    for (size_t i = 1; i < instructions.size(); ++i)
    {
      if (offset == targetOffset)
        return i;
      offset += short_opcode_info(instructions[i].bc).size;
    }
    return instructions.size(); // Not found
  }

  static int calculateOffset(const std::vector<BCInstruction> &instructions, size_t idx)
  {
    int offset = 0;
    for (size_t i = 1; i < idx; ++i)
    {
      offset += short_opcode_info(instructions[i].bc).size;
    }
    return offset;
  }

  static void optimizeJumpSizes(std::vector<BCInstruction> &instructions)
  {
    bool changed;
    do
    {
      changed = false;

      for (size_t i = 1; i < instructions.size(); ++i)
      {
        auto &inst = instructions[i];

        // Try to shrink 32-bit jumps
        if (inst.bc == OP_goto)
        {
          int32_t offset = (int32_t)inst.data.four;
          if (offset >= -128 && offset <= 127)
          {
            inst.bc = OP_goto8;
            inst.valueSize = 1;
            inst.data.one = (uint8_t)offset;
            changed = true;
          }
          else if (offset >= -32768 && offset <= 32767)
          {
            inst.bc = OP_goto16;
            inst.valueSize = 2;
            inst.data.two = (uint16_t)offset;
            changed = true;
          }
        }

        // Try to shrink 32-bit conditional jumps
        if (inst.bc == OP_if_true)
        {
          int32_t offset = (int32_t)inst.data.four;
          if (offset >= -128 && offset <= 127)
          {
            inst.bc = OP_if_true8;
            inst.valueSize = 1;
            inst.data.one = (uint8_t)offset;
            changed = true;
          }
        }

        if (inst.bc == OP_if_false)
        {
          int32_t offset = (int32_t)inst.data.four;
          if (offset >= -128 && offset <= 127)
          {
            inst.bc = OP_if_false8;
            inst.valueSize = 1;
            inst.data.one = (uint8_t)offset;
            changed = true;
          }
        }
      }

      // If we changed sizes, we need to recalculate offsets
      if (changed)
      {
        recalculateJumpOffsets(instructions);
      }
    } while (changed);
  }

  static void recalculateJumpOffsets(std::vector<BCInstruction> &instructions)
  {
    // Store original targets
    std::vector<std::pair<size_t, int>> jumpInfo;

    for (size_t i = 1; i < instructions.size(); ++i)
    {
      if (isJumpInstruction((OPCodeEnum)instructions[i].bc))
      {
        int target = getJumpTarget(instructions, i);
        jumpInfo.push_back({i, target});
      }
    }

    // Recalculate all jump offsets with new instruction sizes
    for (const auto &[idx, targetOffset] : jumpInfo)
    {
      updateJumpTarget(instructions, idx, targetOffset);
    }
  }
};

// Modified generateBytecode function with optimizations
JSValue generateBytecode(JSContext *ctx, IridiumSEXP *node)
{
  IridiumSEXP *file = node;
  ensureTag(file, "File");
  // ensureFlag(file, "JSModule");

  // Entry 1: Module Requests
  // Entry 2: Static Imports
  // Entry 3: Static Exports
  // Entry 4: Static Star Exports
  uint8_t moduleMetaEntries = 4;
  uint16_t numModules = node->numArgs - moduleMetaEntries;

  JSValue *moduleList = (JSValue *)malloc(node->numArgs * sizeof(JSValue));
  int topLevelModuleIdx = -1;

  // Initialize optimizer
  PeepholeOptimizer peepholeOpt;

  for (int i = 0; i < numModules; ++i)
  {
    IridiumSEXP *bbContainer = file->args[moduleMetaEntries + i];
    ensureTag(bbContainer, "BBContainer");

    bool isTopLevelModule = hasFlag(bbContainer, "TopLevel");
    if (isTopLevelModule)
    {
      topLevelModuleIdx = i;
    }

    vector<BCInstruction> instructions;

    // Add dummy first instruction
    BCInstruction inst;
    inst.bc = 0;
    inst.hasPoolData = false;
    inst.poolData = JS_UNINITIALIZED;
    inst.data.four = 0;
    inst.valueSize = 0;
    // inst.isLabel = false;
    // inst.label = 0;
    instructions.push_back(inst);

    // Generate initial bytecode
    IridiumSEXP *bbList = bbContainer->args[1];
    for (int idx = 0; idx < bbList->numArgs; idx++)
    {
      IridiumSEXP *bb = bbList->args[idx];
      ensureTag(bb, "BB");
      pushLabel(ctx, instructions, getFlagNumber(bb, "IDX"));
      for (int stmtIDX = 0; stmtIDX < bb->numArgs; stmtIDX++)
      {
        IridiumSEXP *currStmt = bb->args[stmtIDX];
        handleIriStmt(ctx, instructions, currStmt);
      }
    }

    // Apply optimizations in sequence
    patchGotos(instructions);

    // Apply peephole optimizations
    instructions = peepholeOpt.optimize(instructions);

    // Remove NOPs
    instructions = removeNOPs(ctx, instructions);

    // Optimize jumps (threading and size reduction)
    // JumpOptimizer::optimizeJumps(instructions);

    // Generate the function with optimized instructions
    JSValue res = generateQjsFunction(ctx, bbContainer, instructions);

    // Free BCLList
    freeBCLList(ctx, instructions);

    // js_dump_function_bytecode(ctx, (JSFunctionBytecode *)res.u.ptr);

    moduleList[i] = res;
  }

  assert(topLevelModuleIdx >= 0);

  // Fill CPool with closures (same as before)
  for (int i = 0; i < numModules; i++)
  {
    IridiumSEXP *bbContainer = file->args[moduleMetaEntries+i];
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
        IridiumSEXP *bbContainer = file->args[moduleMetaEntries+k];
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

  if (check_dump_flag(ctx, JS_DUMP_BYTECODE_FINAL))
  {
    fprintf(stdout, "[Iridium] Dumping all non-topLevel module code\n");
  }

  for (int i = 0; i < numModules; i++)
  {
    if (i == topLevelModuleIdx)
      continue;
    JSValue funBC = moduleList[i];
    JSFunctionBytecode *b = (JSFunctionBytecode *)funBC.u.ptr;
    if (check_dump_flag(ctx, JS_DUMP_BYTECODE_FINAL))
    {
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
    if (check_dump_flag(ctx, JS_DUMP_BYTECODE_FINAL))
    {
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
    m->req_module_entries = (JSReqModuleEntry*)js_mallocz(ctx, sizeof(m->req_module_entries[0]) * m->req_module_entries_size);

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
    m->import_entries = (JSImportEntry*)js_mallocz(ctx, sizeof(m->import_entries[0]) * m->import_entries_size);

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
    m->export_entries = (JSExportEntry*)js_mallocz(ctx, sizeof(m->export_entries[0]) * m->export_entries_size);

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
    m->star_export_entries = (JSStarExportEntry*)js_mallocz(ctx, sizeof(m->star_export_entries[0]) * m->star_export_entries_size);

    for (int ex = 0; ex < starExports->numArgs; ++ex)
    {
      IridiumSEXP *starExport = starExports->args[ex];
      // Req IDX
      int reqIDX = getFlagNumber(starExport, "REQIDX");
      m->star_export_entries[ex].req_module_idx = reqIDX;
    }
  }

  if (check_dump_flag(ctx, JS_DUMP_BYTECODE_FINAL))
  {
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
    JSValue moduleVal = JS_NewModuleValue(ctx, (JSModuleDef*)iriRes.ptr);

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
    JSValue moduleVal = JS_NewModuleValue(ctx, (JSModuleDef*)iriRes.ptr);

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
