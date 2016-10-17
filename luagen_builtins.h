typedef struct{
Oid id;
}LuagenContext;

typedef char*  (*codegen_funcexpr)(LuagenContext *context, Expr *node,Oid foreignTableId);
typedef struct{
    Oid                 foid;           /* OID of the function */
    const char *funcName;               /* C name of the function */
    short               nargs;                  /* 0..FUNC_MAX_ARGS, or -1 if variable count */
    bool                strict;                 /* T if function is "strict" */
    bool                retset;                 /* T if function returns a set */
    codegen_funcexpr    func;   /* pointer to compiled function */
} LuagenBuiltin;

char *codegen_expr(LuagenContext *context, Expr *node,Oid foreignTableId);
extern const int luagen_nbuiltins;
