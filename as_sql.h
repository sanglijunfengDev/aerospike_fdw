#ifndef AS_SQL_H
#define AS_SQL_H

#include "postgres.h"
#include "nodes/bitmapset.h"
#include "nodes/primnodes.h"
#include "nodes/value.h"
#include "nodes/parsenodes.h"
#include "utils/tuplestore.h"

#define PG_AEROSPIKE_EXTENSION_NAME "aerospike"

typedef enum PlannerType
{
    PLANNER_INVALID_FIRST = 0,
    PLANNER_TYPE_AEROSPIKE = 1,
    PLANNER_TYPE_POSTGRES = 2,
    PLANNER_TYPE_COMP
} PlannerType;

typedef struct compile_result
{
	Oid tableid;
	char *udf_func_name;
	char *udf_module_name;
	int listlen;
}compile_result;

void aerospike_fdw_init(void);

void aerospike_fdw_fini(void);

compile_result *as_sql_compile(Query *query);

compile_result *as_sql_getcachecompileresult(const char *str_querykey);

bool as_sql_putcachecompileresutl(const char *str_querykey, compile_result *as_compileresult);

compile_result *as_compileudf_file(List *whereColumnList, List *targetList, int listlen, char *clausestr, Oid Foreignid);
#endif   /* AS_SQL_H */
