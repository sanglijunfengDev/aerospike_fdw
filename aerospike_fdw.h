#ifndef AEROSPIKE_FDW_H
#define AEROSPIKE_FDW_H

#include "fmgr.h"
#include "catalog/pg_foreign_server.h"
#include "catalog/pg_foreign_table.h"
#include "utils/hsearch.h"
#include "nodes/pg_list.h"
#include "nodes/relation.h"


#define AEROSPIKE_TUPLE_COST_MULTIPLIER 10

#define OPTION_NAME_SPACE "namespace"
#define OPTION_SET  	  "set"
#define OPTION_KEY        "key"

typedef struct AerospikeValidOption
{
    const char *optionName;
    Oid optionContextId;
} AerospikeValidOption;

typedef struct AerospikeFdwOptions
{
    char *as_namespace;
	char *as_set;
	char *column_key;
} AerospikeFdwOptions;

static const uint32 ValidOptionCount = 3;
static const AerospikeValidOption ValidOptionArray[] =
{
    /* foreign table options */
    { OPTION_NAME_SPACE, ForeignTableRelationId },
    { OPTION_SET, ForeignTableRelationId },
    { OPTION_KEY, ForeignTableRelationId }
};


extern Datum aerospike_fdw_handler(PG_FUNCTION_ARGS);
extern Datum aerospike_fdw_validator(PG_FUNCTION_ARGS);

#endif   /* AEROSPIKE_FDW_H */
