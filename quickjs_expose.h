#include "./quickjs.h"
#include "./list.h"
#ifndef QUICKJS_EXPOSE_H
#define QUICKJS_EXPOSE_H

#ifdef __cplusplus
extern "C"
{
#endif

  JSModuleDef *js_new_module_def(JSContext *ctx, JSAtom name);

  typedef enum JSFunctionKindEnum
  {
    JS_FUNC_NORMAL = 0,
    JS_FUNC_GENERATOR = (1 << 0),
    JS_FUNC_ASYNC = (1 << 1),
    JS_FUNC_ASYNC_GENERATOR = (JS_FUNC_GENERATOR | JS_FUNC_ASYNC),
  } JSFunctionKindEnum;

  // typedef enum {
  //     JS_GC_OBJ_TYPE_JS_OBJECT,
  //     JS_GC_OBJ_TYPE_FUNCTION_BYTECODE,
  //     JS_GC_OBJ_TYPE_SHAPE,
  //     JS_GC_OBJ_TYPE_VAR_REF,
  //     JS_GC_OBJ_TYPE_ASYNC_FUNCTION,
  //     JS_GC_OBJ_TYPE_JS_CONTEXT,
  // } JSGCObjectTypeEnum;

  /* header for GC objects. GC objects are C data structures with a
     reference count that can reference other GC objects. JS Objects are
     a particular type of GC object. */
  struct JSGCObjectHeader
  {
    int ref_count; /* must come first, 32-bit */
    JSGCObjectTypeEnum gc_obj_type : 4;
    uint8_t mark : 4; /* used by the GC */
    uint8_t dummy1;   /* not used by the GC */
    uint16_t dummy2;  /* not used by the GC */
    struct list_head link;
  };

  /* XXX: could use a different structure in bytecode functions to save
     memory */
  typedef struct JSVarDef
  {
    JSAtom var_name;
    /* index into fd->scopes of this variable lexical scope */
    int scope_level;
    /* during compilation:
        - if scope_level = 0: scope in which the variable is defined
        - if scope_level != 0: index into fd->vars of the next
          variable in the same or enclosing lexical scope
       in a bytecode function:
       index into fd->vars of the next
       variable in the same or enclosing lexical scope
    */
    int scope_next;
    uint8_t is_const : 1;
    uint8_t is_lexical : 1;
    uint8_t is_captured : 1;
    uint8_t is_static_private : 1; /* only used during private class field parsing */
    uint8_t var_kind : 4;          /* see JSVarKindEnum */
    /* only used during compilation: function pool index for lexical
       variables with var_kind =
       JS_VAR_FUNCTION_DECL/JS_VAR_NEW_FUNCTION_DECL or scope level of
       the definition of the 'var' variables (they have scope_level =
       0) */
    int func_pool_idx : 24; /* only used during compilation : index in
                               the constant pool for hoisted function
                               definition */
  } JSVarDef;

  typedef struct JSClosureVar
  {
    uint8_t is_local : 1;
    uint8_t is_arg : 1;
    uint8_t is_const : 1;
    uint8_t is_lexical : 1;
    uint8_t var_kind : 4; /* see JSVarKindEnum */
    /* 8 bits available */
    uint16_t var_idx; /* is_local = true: index to a normal variable of the
                    parent function. otherwise: index to a closure
                    variable of the parent function */
    JSAtom var_name;
  } JSClosureVar;

  typedef struct JSFunctionBytecode
  {
    JSGCObjectHeader header; /* must come first */
    uint8_t is_strict_mode : 1;
    uint8_t has_prototype : 1; /* true if a prototype field is necessary */
    uint8_t has_simple_parameter_list : 1;
    uint8_t is_derived_class_constructor : 1;
    /* true if home_object needs to be initialized */
    uint8_t need_home_object : 1;
    uint8_t func_kind : 2;
    uint8_t new_target_allowed : 1;
    uint8_t super_call_allowed : 1;
    uint8_t super_allowed : 1;
    uint8_t arguments_allowed : 1;
    uint8_t backtrace_barrier : 1; /* stop backtrace on this function */
    /* XXX: 5 bits available */
    uint8_t *byte_code_buf; /* (self pointer) */
    int byte_code_len;
    JSAtom func_name;
    JSVarDef *vardefs;         /* arguments + local variables (arg_count + var_count) (self pointer) */
    JSClosureVar *closure_var; /* list of variables in the closure (self pointer) */
    uint16_t arg_count;
    uint16_t var_count;
    uint16_t defined_arg_count; /* for length function property */
    uint16_t stack_size;        /* maximum stack size */
    JSContext *realm;           /* function realm */
    JSValue *cpool;             /* constant pool (self pointer) */
    int cpool_count;
    int closure_var_count;
    JSAtom filename;
    int line_num;
    int col_num;
    int source_len;
    int pc2line_len;
    uint8_t *pc2line_buf;
    char *source;
  } JSFunctionBytecode;

  typedef enum JSErrorEnum
  {
    JS_EVAL_ERROR,
    JS_RANGE_ERROR,
    JS_REFERENCE_ERROR,
    JS_SYNTAX_ERROR,
    JS_TYPE_ERROR,
    JS_URI_ERROR,
    JS_INTERNAL_ERROR,
    JS_AGGREGATE_ERROR,

    JS_NATIVE_ERROR_COUNT, /* number of different NativeError objects */
    JS_PLAIN_ERROR = JS_NATIVE_ERROR_COUNT
  } JSErrorEnum;

  typedef struct JSShapeProperty
  {
    uint32_t hash_next : 26; /* 0 if last in list */
    uint32_t flags : 6;      /* JS_PROP_XXX */
    JSAtom atom;             /* JS_ATOM_NULL = free property entry */
  } JSShapeProperty;

  typedef struct JSShape JSShape;

  struct JSShape
  {
    /* hash table of size hash_mask + 1 before the start of the
       structure (see prop_hash_end()). */
    JSGCObjectHeader header;
    /* true if the shape is inserted in the shape hash table. If not,
       JSShape.hash is not valid */
    uint8_t is_hashed;
    /* If true, the shape may have small array index properties 'n' with 0
       <= n <= 2^31-1. If false, the shape is guaranteed not to have
       small array index properties */
    uint8_t has_small_array_index;
    uint32_t hash; /* current hash value */
    uint32_t prop_hash_mask;
    int prop_size;  /* allocated properties */
    int prop_count; /* include deleted properties */
    int deleted_prop_count;
    JSShape *shape_hash_next; /* in JSRuntime.shape_hash[h] list */
    JSObject *proto;
    JSShapeProperty prop[]; /* prop_size elements */
  };

  struct JSContext
  {
    JSGCObjectHeader header; /* must come first */
    JSRuntime *rt;
    struct list_head link;

    uint16_t binary_object_count;
    int binary_object_size;

    JSShape *array_shape; /* initial shape for Array objects */

    JSValue *class_proto;
    JSValue function_proto;
    JSValue function_ctor;
    JSValue array_ctor;
    JSValue regexp_ctor;
    JSValue promise_ctor;
    JSValue native_error_proto[JS_NATIVE_ERROR_COUNT];
    JSValue error_ctor;
    JSValue error_back_trace;
    JSValue error_prepare_stack;
    JSValue error_stack_trace_limit;
    JSValue iterator_ctor;
    JSValue iterator_proto;
    JSValue async_iterator_proto;
    JSValue array_proto_values;
    JSValue throw_type_error;
    JSValue eval_obj;

    JSValue global_obj;     /* global object */
    JSValue global_var_obj; /* contains the global let/const definitions */

    double time_origin;

    uint64_t random_state;

    /* when the counter reaches zero, JSRutime.interrupt_handler is called */
    int interrupt_counter;

    struct list_head loaded_modules; /* list of JSModuleDef.link */

    /* if NULL, RegExp compilation is not supported */
    JSValue (*compile_regexp)(JSContext *ctx, JSValueConst pattern,
                              JSValueConst flags);
    /* if NULL, eval is not supported */
    JSValue (*eval_internal)(JSContext *ctx, JSValueConst this_obj,
                             const char *input, size_t input_len,
                             const char *filename, int line, int flags, int scope_idx);
    void *user_opaque;
  };

  typedef struct JSRefCountHeader
  {
    int ref_count;
  } JSRefCountHeader;

  typedef struct JSReqModuleEntry
  {
    JSAtom module_name;
    JSModuleDef *module; /* used using resolution */
  } JSReqModuleEntry;

  typedef enum JSExportTypeEnum
  {
    JS_EXPORT_TYPE_LOCAL,
    JS_EXPORT_TYPE_INDIRECT,
  } JSExportTypeEnum;

  typedef struct JSVarRef
  {
    union
    {
      JSGCObjectHeader header; /* must come first */
      struct
      {
        int __gc_ref_count; /* corresponds to header.ref_count */
        uint8_t __gc_mark;  /* corresponds to header.mark/gc_obj_type */
        bool is_detached;
      };
    };
    JSValue *pvalue; /* pointer to the value, either on the stack or
                        to 'value' */
    JSValue value;   /* used when the variable is no longer on the stack */
  } JSVarRef;

  typedef struct JSExportEntry
  {
    union
    {
      struct
      {
        int var_idx;       /* closure variable index */
        JSVarRef *var_ref; /* if != NULL, reference to the variable */
      } local;             /* for local export */
      int req_module_idx;  /* module for indirect export */
    } u;
    JSExportTypeEnum export_type;
    JSAtom local_name;  /* '*' if export ns from. not used for local
                           export after compilation */
    JSAtom export_name; /* exported variable name */
  } JSExportEntry;

  typedef struct JSStarExportEntry
  {
    int req_module_idx; /* in req_module_entries */
  } JSStarExportEntry;

  typedef struct JSImportEntry
  {
    int var_idx; /* closure variable index */
    JSAtom import_name;
    int req_module_idx; /* in req_module_entries */
  } JSImportEntry;

  typedef enum
  {
    JS_MODULE_STATUS_UNLINKED,
    JS_MODULE_STATUS_LINKING,
    JS_MODULE_STATUS_LINKED,
    JS_MODULE_STATUS_EVALUATING,
    JS_MODULE_STATUS_EVALUATING_ASYNC,
    JS_MODULE_STATUS_EVALUATED,
  } JSModuleStatus;

  struct JSModuleDef
  {
    JSRefCountHeader header; /* must come first, 32-bit */
    JSAtom module_name;
    struct list_head link;

    JSReqModuleEntry *req_module_entries;
    int req_module_entries_count;
    int req_module_entries_size;

    JSExportEntry *export_entries;
    int export_entries_count;
    int export_entries_size;

    JSStarExportEntry *star_export_entries;
    int star_export_entries_count;
    int star_export_entries_size;

    JSImportEntry *import_entries;
    int import_entries_count;
    int import_entries_size;

    JSValue module_ns;
    JSValue func_obj;            /* only used for JS modules */
    JSModuleInitFunc *init_func; /* only used for C modules */
    bool has_tla;                /* true if func_obj contains await */
    bool resolved;
    bool func_created;
    JSModuleStatus status : 8;
    /* temp use during js_module_link() & js_module_evaluate() */
    int dfs_index, dfs_ancestor_index;
    JSModuleDef *stack_prev;
    /* temp use during js_module_evaluate() */
    JSModuleDef **async_parent_modules;
    int async_parent_modules_count;
    int async_parent_modules_size;
    int pending_async_dependencies;
    bool async_evaluation;
    int64_t async_evaluation_timestamp;
    JSModuleDef *cycle_root;
    JSValue promise;            /* corresponds to spec field: capability */
    JSValue resolving_funcs[2]; /* corresponds to spec field: capability */
    /* true if evaluation yielded an exception. It is saved in
       eval_exception */
    bool eval_has_exception;
    JSValue eval_exception;
    JSValue meta_obj; /* for import.meta */
  };

  JSValue JS_NewModuleValue(JSContext *ctx, JSModuleDef *m);

  void js_dump_function_bytecode(JSContext *ctx, JSFunctionBytecode *b);

#ifdef __cplusplus
}
#endif

#endif /* QUICKJS_EXPOSE_H */
