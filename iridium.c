#include "./iridium.h"
#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"
#include "./quickjs_expose.h"
#include "./quickjs-opcode.h"

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
    res->args[i] = handleIridiumSEXP(cJSON_GetArrayItem(args, i));
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

IridiumSEXP *handleIridiumSEXP(cJSON *node)
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

JSValue create_hello_world(JSContext *ctx)
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
    OP_return_async
  };

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
    return JS_EXCEPTION;

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

  /* Return function */
  return JS_MKPTR(JS_TAG_FUNCTION_BYTECODE, b);
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

  IridiumSEXP *iridiumCode = handleIridiumSEXP(code);

  dumpIridiumSEXP(stdout, iridiumCode, 0);

  // Create function object
  JSValue fun_obj = create_hello_world(ctx);
  JSModuleDef *m = js_new_module_def(ctx, JS_NewAtom(ctx, "<unnamed>"));
  m->func_obj = fun_obj;

  fun_obj = JS_NewModuleValue(ctx, m);

  // === Now actually call the function ===
  // JSValue ret =
  // JS_Call(ctx, fun_obj, JS_TRUE, 0, NULL);
  JS_EvalFunction(ctx, fun_obj);


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
