#include "./iridium.h"
#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"
#include "./quickjs_expose.h"
#include "./quickjs-opcode.h"
#include "./cutils.h"
#include <assert.h>

typedef enum OPCodeFormat
{
#define FMT(f) OP_FMT_##f,
#define DEF(id, size, n_pop, n_push, f)
#include "quickjs-opcode.h"
#undef DEF
#undef FMT
} OPCodeFormat;

typedef enum {
    /* XXX: add more variable kinds here instead of using bit fields */
    JS_VAR_NORMAL,
    JS_VAR_FUNCTION_DECL, /* lexical var with function declaration */
    JS_VAR_NEW_FUNCTION_DECL, /* lexical var with async/generator
                                 function declaration */
    JS_VAR_CATCH,
    JS_VAR_FUNCTION_NAME, /* function expression name */
    JS_VAR_PRIVATE_FIELD,
    JS_VAR_PRIVATE_METHOD,
    JS_VAR_PRIVATE_GETTER,
    JS_VAR_PRIVATE_SETTER, /* must come after JS_VAR_PRIVATE_GETTER */
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
  // Extend the data structure to accomodate arguments dynamically
} BCLList;

// ============== Push OP ============== //
BCLList *pushLabel(JSContext *ctx, BCLList *currTarget, int label)
{
  currTarget->next = js_mallocz(ctx, sizeof(BCLList));
  currTarget = currTarget->next;
  currTarget->next = NULL;
  currTarget->bc = OP_nop;
  currTarget->hasPoolData = false;
  currTarget->poolData = JS_UNINITIALIZED;
  currTarget->isLabel = true;
  currTarget->label = label;
  currTarget->valueSize = 0;
  currTarget->data.four = 0;
  return currTarget;
}

BCLList *pushOP(JSContext *ctx, BCLList *currTarget, OPCodeEnum opcode)
{
  currTarget->next = js_mallocz(ctx, sizeof(BCLList));
  currTarget = currTarget->next;
  currTarget->next = NULL;
  currTarget->bc = opcode;
  currTarget->hasPoolData = false;
  currTarget->poolData = JS_UNINITIALIZED;
  currTarget->isLabel = false;
  currTarget->label = 0;
  currTarget->valueSize = 0;
  currTarget->data.four = 0;
  return currTarget;
}

BCLList *pushOP8(JSContext *ctx, BCLList *currTarget, OPCodeEnum opcode, uint8_t data)
{
  currTarget->next = js_mallocz(ctx, sizeof(BCLList));
  currTarget = currTarget->next;
  currTarget->next = NULL;
  currTarget->bc = opcode;
  currTarget->hasPoolData = false;
  currTarget->poolData = JS_UNINITIALIZED;
  currTarget->isLabel = false;
  currTarget->label = 0;
  currTarget->valueSize = 1;
  currTarget->data.one = data;
  return currTarget;
}

BCLList *pushOP16(JSContext *ctx, BCLList *currTarget, OPCodeEnum opcode, uint16_t data)
{
  currTarget->next = js_mallocz(ctx, sizeof(BCLList));
  currTarget = currTarget->next;
  currTarget->next = NULL;
  currTarget->bc = opcode;
  currTarget->hasPoolData = false;
  currTarget->poolData = JS_UNINITIALIZED;
  currTarget->isLabel = false;
  currTarget->label = 0;
  currTarget->valueSize = 2;
  currTarget->data.two = data;
  return currTarget;
}

BCLList *pushOP32(JSContext *ctx, BCLList *currTarget, OPCodeEnum opcode, uint32_t data)
{
  currTarget->next = js_mallocz(ctx, sizeof(BCLList));
  currTarget = currTarget->next;
  currTarget->next = NULL;
  currTarget->bc = opcode;
  currTarget->hasPoolData = false;
  currTarget->poolData = JS_UNINITIALIZED;
  currTarget->isLabel = false;
  currTarget->label = 0;
  currTarget->valueSize = 4;
  currTarget->data.four = data;
  return currTarget;
}

BCLList *pushOPConst(JSContext *ctx, BCLList *currTarget, OPCodeEnum opcode, JSValue cData)
{
  currTarget->next = js_mallocz(ctx, sizeof(BCLList));
  currTarget = currTarget->next;
  currTarget->next = NULL;
  currTarget->bc = opcode;
  currTarget->hasPoolData = true;
  currTarget->poolData = cData;
  currTarget->isLabel = false;
  currTarget->label = 0;
  currTarget->valueSize = 4;
  currTarget->data.four = 0;
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

BCLList *lowerToStack(JSContext *ctx, BCLList *currTarget, IridiumSEXP *rval)
{
  if (isTag(rval, "String"))
  {
    char *data = getFlagString(rval, "IridiumPrimitive");
    JSAtom strAtom = JS_NewAtom(ctx, data);
    return pushOP32(ctx, currTarget, OP_push_atom_value, strAtom);
  }
  else if (isTag(rval, "Number"))
  {
    int data = getFlagNumber(rval, "IridiumPrimitive");
    JSValue jsvalue = JS_NewNumber(ctx, data);
    return pushOPConst(ctx, currTarget, OP_push_const, jsvalue);
  }
  else if (isTag(rval, "JSNUBD"))
  {
    return pushOPConst(ctx, currTarget, OP_push_const, JS_UNINITIALIZED);
  }
  else if (isTag(rval, "EnvBinding"))
  {
    int refIDX = getFlagNumber(rval, "REFIDX");
    if (hasFlag(rval, "ClosureVAR")) {
      return pushOP16(ctx, currTarget, OP_get_var_ref, refIDX);
    } else {
      return pushOP16(ctx, currTarget, OP_get_loc, refIDX);
    }
  }
  else if (isTag(rval, "GlobalBinding"))
  {
    return pushOP32(ctx, currTarget, OP_get_var, JS_NewAtom(ctx, getFlagString(rval->args[0], "IridiumPrimitive")));
  }
  else if (isTag(rval, "CallSiteSEXP"))
  {
    for (int i = 0; i < rval->numArgs; i++) {
      currTarget = lowerToStack(ctx, currTarget, rval->args[i]);
    }
    if (hasFlag(rval, "CCall")) {
      return pushOP16(ctx, currTarget, OP_call_method, rval->numArgs - 2);
    } else {
      return pushOP16(ctx, currTarget, OP_call, rval->numArgs - 1);
    }
  }
  else if (isTag(rval, "EnvRead"))
  {
    return lowerToStack(ctx, currTarget, rval->args[0]);
  }
  else if (isTag(rval, "Binop"))
  {
    char * op = getFlagString(rval->args[0], "IridiumPrimitive");
    if (strcmp(op, "+") == 0) {
      currTarget = lowerToStack(ctx, currTarget, rval->args[1]);
      currTarget = lowerToStack(ctx, currTarget, rval->args[2]);
      return pushOP(ctx, currTarget, OP_add);
    } else {
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
    return pushOP32(ctx, currTarget, OP_get_field2, fieldAtom);
  }
  else
  {
    fprintf(stderr, "TODO: unhandled RVal: %s\n", rval->tag);
    exit(1);
  }

  return currTarget;
}

bool isSimpleAssignment(IridiumSEXP *currStmt)
{
  return currStmt->numArgs == 2 && isTag(currStmt->args[0], "EnvBinding");
}

BCLList *handleEnvWrite(JSContext *ctx, BCLList *currTarget, IridiumSEXP *currStmt)
{
  // BINDING = VAL
  if (isSimpleAssignment(currStmt))
  {
    // Lower RVal
    currTarget = lowerToStack(ctx, currTarget, currStmt->args[1]);

    IridiumSEXP *binding = currStmt->args[0];
    int refIdx = getFlagNumber(binding, "REFIDX");

    // Write to LocalVar
    if (hasFlag(binding, "ClosureVAR"))
    {
      currTarget = pushOP16(ctx, currTarget, OP_put_var_ref, refIdx);
    }
    else if (hasFlag(binding, "LocalVAR"))
    {
      currTarget = pushOP16(ctx, currTarget, OP_put_loc, refIdx);
    }
    else
    {
      fprintf(stderr, "TODO: Binding kind not specified!!");
      exit(1);
    }
  }
  else
  {
    fprintf(stderr, "TODO: unhandled env write: %s\n", currStmt->tag);
    exit(1);
  }

  return currTarget;
}

BCLList *handleIriStmt(JSContext *ctx, BCLList *currTarget, IridiumSEXP *currStmt)
{
  if (isTag(currStmt, "EnvWrite"))
  {
    return handleEnvWrite(ctx, currTarget, currStmt);
  }
  else if (isTag(currStmt, "Goto"))
  {
    return pushOP32(ctx, currTarget, OP_goto, getFlagNumber(currStmt, "IDX"));
  }
  else
  {
    fprintf(stderr, "TODO: unhandled tag: %s\n", currStmt->tag);
    exit(1);
  }
  return currTarget;
}

int getPoolSize(BCLList * bcList) {
  if (bcList) {
    if (bcList->hasPoolData) {
      return 1 + getPoolSize(bcList->next);
    }
    return getPoolSize(bcList->next);
  }
  return 0;
}

int getBCSize(BCLList * bcList) {
  if (bcList) {
    return short_opcode_info(bcList->bc).size + getBCSize(bcList->next);
  }
  return 0;
}

void populateCPool(JSContext *ctx, BCLList * bcList, JSValue * cpool) {
  if (bcList) {
    if (bcList->hasPoolData) {
      uint32_t offset = bcList->data.four;
      *(cpool + offset) = JS_DupValue(ctx, bcList->poolData);
    }
    return populateCPool(ctx, bcList->next, cpool);
  }
}

int findOffset(BCLList * bcList, int offset, int targetOffset) {
  if (bcList) {
    if (bcList->isLabel && bcList->label == targetOffset) {
      return offset + short_opcode_info(bcList->bc).size - 1;
    } else {
      return findOffset(bcList->next, offset + short_opcode_info(bcList->bc).size, targetOffset);
    }
  }
  fprintf(stderr, "Failed to find BC offset for %d\n", targetOffset);
  exit(1);
}

void patchGotos(BCLList * bcList, int currOffset, BCLList * startBcList) {
  if (bcList) {
    if (bcList->bc == OP_goto) {
      uint32_t iriOffset = bcList->data.four;
      int actualOffset = findOffset(startBcList, 0, iriOffset);
      fprintf(stdout, "Patching offset %d to %d\n", iriOffset, actualOffset);
      bcList->data.four = actualOffset - currOffset;
    }
    patchGotos(bcList->next, currOffset + short_opcode_info(bcList->bc).size, startBcList);
  }
}

void freeBCList(JSContext *ctx, BCLList * bcList) {
  if (bcList) {
    freeBCList(ctx, bcList->next);
    if (bcList->hasPoolData) {
      JS_FreeValue(ctx, bcList->poolData);
    }
    js_free(ctx, bcList);
  }
}

void populateBytecode(uint8_t * target, BCLList * currBC, int poolIDX) {
  if (!currBC) return;
  if (currBC->hasPoolData) {
    currBC->data.four = poolIDX++;
    assert(currBC->valueSize == 4);
  }
  target[0] = currBC->bc;
  if (currBC->valueSize == 1) {
    uint8_t * t = (uint8_t *) (target + 1);
    *t = currBC->data.one;
  } else if (currBC->valueSize == 2) {
    uint16_t * t = (uint16_t *) (target + 1);
    *t = currBC->data.two;
  } else if (currBC->valueSize == 4) {
    uint32_t * t = (uint32_t *) (target + 1);
    *t = currBC->data.four;
  }
  return populateBytecode(target + short_opcode_info(currBC->bc).size, currBC->next, poolIDX);
}


BCLList **generateBytecode(JSContext *ctx, IridiumSEXP *node)
{
  IridiumSEXP *file = node;
  ensureTag(file, "File");
  ensureFlag(file, "JSModule");

  IridiumSEXP *scopeDescriptors = file->args[0];
  ensureTag(scopeDescriptors, "ScopeDescriptorContainer");

  BCLList **bcList = js_mallocz(ctx, (node->numArgs - 1) * sizeof(BCLList *));

  for (int i = 1; i < file->numArgs; ++i)
  {
    IridiumSEXP *bbContainer = file->args[i];
    ensureTag(bbContainer, "BBContainer");

    BCLList *bcTarget = js_mallocz(ctx, sizeof(BCLList));
    BCLList *temp = bcTarget;
    BCLList *startBC = bcTarget;
    bcList[i] = bcTarget;

    bcTarget->next = NULL;
    bcTarget->bc = 0;
    bcTarget->hasPoolData = false;
    bcTarget->poolData = JS_UNINITIALIZED;
    bcTarget->data.four = 0;
    bcTarget->valueSize = 0;

    // Module Header
    bcTarget = pushOP(ctx, bcTarget, OP_push_this);
    bcTarget = pushOP8(ctx, bcTarget, OP_if_false8, 2);
    bcTarget = pushOP(ctx, bcTarget, OP_return_undef);

    // Module Body
    for (int idx = 0; idx < bbContainer->numArgs; idx++)
    {
      IridiumSEXP *bb = bbContainer->args[idx];
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

    // Module Exit
    bcTarget = pushOP(ctx, bcTarget, OP_undefined);
    bcTarget = pushOP(ctx, bcTarget, OP_return_async);

    int i = 0;
    temp = startBC->next;
    while (temp)
    {
      fprintf(stdout, "BC[%d]: %s (size = %d bytes)", i, short_opcode_info(temp->bc).name, short_opcode_info(temp->bc).size);
      assert(short_opcode_info(temp->bc).size == (temp->valueSize + 1));

      if (temp->bc == OP_push_const)
      {
        JSValue jsvalue = temp->poolData;
        fprintf(stdout, ", CPool: \"%s\"\n", JS_ToCString(ctx, jsvalue));
      }
      else if (temp->bc == OP_push_atom_value || temp->bc == OP_get_var || temp->bc == OP_get_field2)
      {
        fprintf(stdout, ", StringData(%d): \"%s\"\n", temp->data.four, JS_AtomToCString(ctx, temp->data.four));
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

    int poolSize = getPoolSize(startBC->next);
    int varDefSize = getFlagNumber(bbContainer, "LocalVAR");
    int closureVarSize = getFlagNumber(bbContainer, "ClosureVAR");
    int bcSize = getBCSize(startBC->next);

    int function_size = sizeof(JSFunctionBytecode);
    int cpool_offset = function_size;
    function_size += poolSize * sizeof(JSValue);
    int vardefs_offset = function_size;
    function_size += varDefSize * sizeof(JSVarDef);
    int closure_var_offset = function_size;
    function_size += closureVarSize * sizeof(JSClosureVar);
    int byte_code_offset = function_size;
    function_size += bcSize;

    JSFunctionBytecode *b = js_mallocz(ctx, function_size);
    if (!b) {
      fprintf(stderr, "Failed to create bytecode");
      exit(1);
    }
    b->header.ref_count = 1;
    b->header.gc_obj_type = JS_GC_OBJ_TYPE_FUNCTION_BYTECODE;

    // Self Pointers
    b->cpool = (JSValue *)((uint8_t *)b + cpool_offset);
    b->vardefs = (JSVarDef *)((uint8_t *)b + vardefs_offset);
    b->byte_code_buf = (uint8_t *)b + byte_code_offset;
    b->closure_var = (void *)((uint8_t*)b + closure_var_offset);

    for (int i = 0; i < closureVarSize; i++) {
      b->closure_var[i].is_local = true;
      b->closure_var[i].is_arg = false;
      b->closure_var[i].is_const = false;
      b->closure_var[i].is_lexical = false;
      b->closure_var[i].var_kind = JS_VAR_NORMAL;
      b->closure_var[i].var_idx = i;
      b->closure_var[i].var_name = JS_NewAtom(ctx, "TEMP");
    }

    b->cpool_count = poolSize;
    b->var_count = varDefSize;
    b->arg_count = 0;
    b->defined_arg_count = 0;
    b->stack_size = 4;
    b->closure_var_count = closureVarSize;
    b->byte_code_len = bcSize;
    b->func_name = JS_ATOM_NULL;
    b->has_prototype = 0;
    b->has_simple_parameter_list = 0;
    b->is_strict_mode = 1;
    b->func_kind = JS_FUNC_NORMAL;
    b->realm = JS_DupContext(ctx);

    // Populate Bytecode from BCLList
    populateBytecode(b->byte_code_buf, startBC->next, 0);
    populateCPool(ctx, startBC->next, b->cpool);
    freeBCList(ctx, startBC);

    JSRuntime *rt = ctx->rt;
    /* Insert into GC */
    add_gc_object(rt, &b->header, JS_GC_OBJ_TYPE_FUNCTION_BYTECODE);
  
    JSValue fun_obj = JS_MKPTR(JS_TAG_FUNCTION_BYTECODE, b);
  
    JSModuleDef *m = js_new_module_def(ctx, JS_NewAtom(ctx, "<unnamed>"));
    m->func_obj = fun_obj;

    JSValue module_obj = JS_NewModuleValue(ctx, m);

    js_dump_function_bytecode(ctx, b);

    JSValue res = JS_EvalFunction(ctx, module_obj);
    
    JS_FreeValue(ctx, res);
    JS_FreeValue(ctx, fun_obj);
  }

  return bcList;
}

void hello_world_test(JSContext *ctx)
{
  JSRuntime *rt = ctx->rt;
  JSAtom atom_console = JS_NewAtom(ctx, "console");
  JSAtom atom_log = JS_NewAtom(ctx, "log");
  JSAtom atom_hello_world = JS_NewAtom(ctx, "Hello World");
  uint16_t callMethodStackSize = 1;

  uint8_t bytecode[] = {
      OP_push_this,
      OP_if_false8,
      2,
      OP_return_undef,
      OP_get_var,
      0, 0, 0, 0, // 32 bytes for console atom 'console'
      OP_get_field2,
      0, 0, 0, 0, // 32 bytes for console atom 'log'
      OP_push_atom_value,
      0, 0, 0, 0, // 32 bytes for console atom 'Hello World'
      OP_call_method,
      0, 0,
      OP_drop,
      OP_undefined,
      OP_return_async};

  memcpy(bytecode + 5, &atom_console, 4 * sizeof(uint8_t));
  memcpy(bytecode + 10, &atom_log, 4 * sizeof(uint8_t));
  memcpy(bytecode + 15, &atom_hello_world, 4 * sizeof(uint8_t));
  memcpy(bytecode + 20, &callMethodStackSize, 2 * sizeof(uint8_t));

  int function_size = sizeof(JSFunctionBytecode);
  int cpool_count = 0;
  int var_count = 0;
  int byte_code_len = sizeof(bytecode);

  int cpool_offset = function_size;
  function_size += sizeof(JSValue) * cpool_count;

  int vardefs_offset = function_size;
  function_size += sizeof(JSVarDef) * var_count;

  int bytecode_offset = function_size;
  function_size += byte_code_len;

  JSFunctionBytecode *b = js_mallocz(ctx, function_size);
  if (!b)
    return;

  b->header.ref_count = 1;
  b->header.gc_obj_type = JS_GC_OBJ_TYPE_FUNCTION_BYTECODE;

  b->cpool = (JSValue *)((uint8_t *)b + cpool_offset);
  b->vardefs = (JSVarDef *)((uint8_t *)b + vardefs_offset);
  b->byte_code_buf = (uint8_t *)b + bytecode_offset;

  b->cpool_count = cpool_count;
  b->var_count = var_count;
  b->arg_count = 0;
  b->defined_arg_count = 0;
  b->stack_size = 8;
  b->closure_var_count = 0;
  b->byte_code_len = byte_code_len;
  b->func_name = JS_ATOM_NULL;
  b->has_prototype = 1;
  b->has_simple_parameter_list = 1;
  b->is_strict_mode = 1;
  b->func_kind = JS_FUNC_NORMAL;
  b->realm = JS_DupContext(ctx);

  /* Copy bytecode */
  memcpy(b->byte_code_buf, bytecode, byte_code_len);

  /* Insert into GC */
  add_gc_object(rt, &b->header, JS_GC_OBJ_TYPE_FUNCTION_BYTECODE);

  // Evaluate
  JSValue fun_obj = JS_MKPTR(JS_TAG_FUNCTION_BYTECODE, b);
  JSModuleDef *m = js_new_module_def(ctx, JS_NewAtom(ctx, "<unnamed>"));
  m->func_obj = fun_obj;

  JSValue module_obj = JS_NewModuleValue(ctx, m);

  JSValue retVal = JS_EvalFunction(ctx, module_obj);
  
  JS_FreeValue(ctx, retVal);
  JS_FreeValue(ctx, fun_obj);

  return;
}

void eval_iri_file(JSContext *ctx, const char *filename)
{
  fprintf(stdout, "[1] Loading Iridium Module\n");
  cJSON *json = load_json(filename);

  if (json == NULL)
  {
    printf("Failed to load JSON.\n");
    return;
  }

  cJSON *code = cJSON_GetObjectItem(json, "iridium");

  if (!cJSON_IsArray(code))
  {
    fprintf(stderr, "Expected the iridium key to be an array...");
    exit(1);
  }

  IridiumSEXP *iridiumCode = parseIridiumSEXP(code);

  // Generate BC

  generateBytecode(ctx, iridiumCode);

  // dumpIridiumSEXP(stdout, iridiumCode, 0);

  // Create function object
  // JSValue fun_obj = 
  // hello_world_test(ctx);
  // JSModuleDef *m = js_new_module_def(ctx, JS_NewAtom(ctx, "<unnamed>"));
  // m->func_obj = fun_obj;

  // fun_obj = JS_NewModuleValue(ctx, m);

  // JS_EvalFunction(ctx, fun_obj);
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
