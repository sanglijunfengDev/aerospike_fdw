#include "as_sql.h"
#include "postgres.h"

#include "commands/extension.h"
#include "executor/execdesc.h"
#include "executor/executor.h"
#include "nodes/makefuncs.h"
#include "nodes/nodeFuncs.h"
#include "nodes/nodes.h"
#include "nodes/params.h"
#include "nodes/parsenodes.h"
#include "nodes/plannodes.h"
#include "nodes/primnodes.h"
#include "optimizer/clauses.h"
#include "optimizer/cost.h"
#include "optimizer/planner.h"
#include "optimizer/var.h"
#include "parser/analyze.h"
#include "parser/parse_node.h"
#include "parser/parsetree.h"
#include "parser/parse_type.h"
#include "storage/lock.h"
#include "catalog/pg_class.h"
#include "foreign/fdwapi.h"
#include "foreign/foreign.h"
#include "utils/syscache.h"
#include "utils/lsyscache.h"
#include "utils/builtins.h"
#include "utils/rel.h"
#include "access/htup_details.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_namespace.h"

static PlannedStmt *as_planner(Query *query, int cursorOptions, ParamListInfo boundParams);
static PlannerType DeterminePlannerType(Query *query);
static planner_hook_type PreviousPlannerHook = NULL;

void aerospike_fdw_init(void)
{
    PreviousPlannerHook = planner_hook;
    planner_hook = as_planner;
}


void aerospike_fdw_fini(void)
{
    planner_hook = PreviousPlannerHook;
}

#define AEROSPIKE_FDW_NAME "aerospike_fdw"

static bool AerospikeTable(Oid relationId)
{
    bool aerospikeTable = false;
    char relationKind = 0;

    if (relationId == InvalidOid)
    {
        return false;
    }

    relationKind = get_rel_relkind(relationId);
    if (relationKind == RELKIND_FOREIGN_TABLE)
    {
        ForeignTable *foreignTable = GetForeignTable(relationId);
        ForeignServer *server = GetForeignServer(foreignTable->serverid);
        ForeignDataWrapper *foreignDataWrapper = GetForeignDataWrapper(server->fdwid);

        char *foreignWrapperName = foreignDataWrapper->fdwname;
        if (strncmp(foreignWrapperName, AEROSPIKE_FDW_NAME, NAMEDATALEN) == 0)
        {
            aerospikeTable = true;
        }
    }

    return aerospikeTable;
}
/*
 * ExtractRangeTableEntryWalker walks over a query tree, and finds all range
 * table entries. For recursing into the query tree, this function uses the
 * query tree walker since the expression tree walker doesn't recurse into
 * sub-queries.
 */
static bool
ExtractRangeTableEntryWalker(Node *node, List **rangeTableList)
{
    bool walkIsComplete = false;
    if (node == NULL)
    {
        return false;
    }

    if (IsA(node, RangeTblEntry))
    {
        RangeTblEntry *rangeTable = (RangeTblEntry *) node;
        if (AerospikeTable(rangeTable->relid))
        {
            (*rangeTableList) = lappend(*rangeTableList, rangeTable);
        }
    }
    else if (IsA(node, Query))
    {
        walkIsComplete = query_tree_walker((Query *) node, ExtractRangeTableEntryWalker,
                                            rangeTableList, QTW_EXAMINE_RTES);
    }
    else
    {
    	walkIsComplete = expression_tree_walker(node, ExtractRangeTableEntryWalker,
                                                rangeTableList);
    }

    return walkIsComplete;
}

static PlannerType
DeterminePlannerType(Query *query)
{
    PlannerType plannerType = PLANNER_INVALID_FIRST;
    CmdType commandType = query->commandType;

    /* if the extension isn't created, we always use the postgres planner */
    bool missingOK = true;
    Oid extensionOid = get_extension_oid(PG_AEROSPIKE_EXTENSION_NAME, missingOK);
    if (extensionOid == InvalidOid)
    {
        return PLANNER_TYPE_POSTGRES;
    }

    if (commandType == CMD_SELECT || commandType == CMD_INSERT ||
    		 commandType == CMD_UPDATE || commandType == CMD_DELETE)
    {
        List *rangeTableList = NIL;
        ExtractRangeTableEntryWalker((Node *) query, &rangeTableList);
        if (rangeTableList != NULL)
        {
           plannerType = PLANNER_TYPE_AEROSPIKE;
        }
        else
        {
            plannerType = PLANNER_TYPE_POSTGRES;
        }
    }
    else
    {
        /*
         * For utility statements, we need to detect if they are operating on
         * distributed tables. If they are, we need to warn or error out
         * accordingly.
         */
        plannerType = PLANNER_TYPE_POSTGRES;
    }

    return plannerType;
}

static PlannedStmt *as_planner(Query *query, int cursorOptions, ParamListInfo boundParams)
{
    List *table_list = NULL;
    PlannedStmt *plannedStatement = NULL;

    PlannerType plannerType = DeterminePlannerType(query);

    if (plannerType == PLANNER_TYPE_AEROSPIKE)
    {
        /* FIXME:do something to compile udf file */
        plannedStatement = standard_planner(query, cursorOptions, boundParams);
        return plannedStatement;
    }
    else if (plannerType == PLANNER_TYPE_POSTGRES)
    {
        if (PreviousPlannerHook != NULL)
        {
            plannedStatement = PreviousPlannerHook(query, cursorOptions, boundParams);
        }
        else
        {
            plannedStatement = standard_planner(query, cursorOptions, boundParams);
        }
    }
    else
    {
        ereport(ERROR, (errmsg("unrecognized planner type: %d", plannerType)));
    }

    return plannedStatement;
}
