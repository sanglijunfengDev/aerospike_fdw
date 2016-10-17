#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "postgres.h"
#include "aerospike_fdw.h"

#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include "access/htup_details.h"
#include "access/reloptions.h"
#include "access/sysattr.h"
#include "catalog/namespace.h"
#include "catalog/pg_foreign_table.h"
#include "commands/copy.h"
#include "commands/defrem.h"
#include "commands/event_trigger.h"
#include "commands/explain.h"
#include "commands/vacuum.h"
#include "foreign/fdwapi.h"
#include "foreign/foreign.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "optimizer/cost.h"
#include "optimizer/pathnode.h"
#include "optimizer/planmain.h"
#include "optimizer/restrictinfo.h"
#include "optimizer/var.h"
#include "tcop/utility.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "utils/lsyscache.h"
#include "utils/jsonb.h"
#include "parser/parse_coerce.h"
#include "parser/parse_relation.h"
#include "utils/rel.h"
#include "luagen_builtins.h"
#include "as_sql.h"
#include "utils/timestamp.h"

#include <aerospike/aerospike.h>
#include <aerospike/aerospike_key.h>
#include <aerospike/aerospike_lmap.h>
#include <aerospike/as_record_iterator.h>
#include <aerospike/as_error.h>
#include <aerospike/as_hashmap.h>
#include <aerospike/as_hashmap_iterator.h>
#include <aerospike/as_ldt.h>
#include <aerospike/as_list.h>
#include <aerospike/as_record.h>
#include <aerospike/as_arraylist.h>
#include <aerospike/as_stringmap.h>
#include <aerospike/as_val.h>
#include <aerospike/as_query.h>
#include <citrusleaf/cf_queue.h>

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

typedef struct as_context
{
	Oid foreignTableId;
	cf_queue *context;
	pthread_t id;
	TupleDesc	tupleDescriptor;
}as_context;

aerospike as;
aerospike as_ip2location;
char *as_server_ip;
int as_server_port;

#define RIAttName(rel, attnum)	NameStr(*attnumAttName(rel, attnum))
compile_result *g_compile_result;

#define BUFFSIZE    256
PG_FUNCTION_INFO_V1(aerospike_fdw_handler);
PG_FUNCTION_INFO_V1(aerospike_fdw_validator);

static AerospikeFdwOptions *AerospikeGetOptions(Oid foreignTableId);

static void AsGetForeignRelSize(PlannerInfo *root, RelOptInfo *baserel, Oid foreignTableId);
static void AsGetForeignPaths(PlannerInfo *root, RelOptInfo *baserel, Oid foreignTableId);
static ForeignScan * AsGetForeignPlan(PlannerInfo *root, RelOptInfo *baserel, Oid foreignTableId,
                                      ForeignPath *bestPath, List *targetList, List *scanClauses,Plan *outer_plan);
static List *AsPlanForeignModify(PlannerInfo *plannerInfo, ModifyTable *plan,
                                 Index resultRelation, int subplanIndex);
static void AsBeginForeignModify(ModifyTableState *modifyTableState,
                                 ResultRelInfo *relationInfo, List *fdwPrivate,
                                 int subplanIndex, int executorFlags);
static TupleTableSlot *AsExecForeignInsert(EState *executorState, ResultRelInfo *relationInfo,
                                           TupleTableSlot *tupleSlot, TupleTableSlot *planSlot);
static void AsEndForeignModify(EState *executorState, ResultRelInfo *relationInfo);

static void BeginScanAsRelation(ForeignScanState *scanState, int executorFlags);

static TupleTableSlot *AsScanNext(ForeignScanState *scanState);

static void EndScanAsRelation(ForeignScanState *scanState);

static List *ColumnList(RelOptInfo *baserel);

static bool remove_udf_module(aerospike* p_as, const char* udf_file_path);
static bool insert_as_record(Oid foreignTableId,
                             Oid *att_type,
                             Datum *values,
                             char **attr_name,
                             int cloumn,
                             bool *columnNulls);

void Connect_to_aerospike_with_udf_configtmp(aerospike* p_as, char *as_server_ip,
                                             int as_server_port, const char* lua_user_path)
{
        as_config cfg;
        as_error err;
        as_config_init(&cfg);
        as_config_add_host(&cfg, as_server_ip, as_server_port);
	as_config_host *host;

    int rc = access(cfg.lua.system_path, R_OK);
    if (rc != 0)
    {
	// Use lua files in source tree if they exist.         
        char* path = "/home/pg/lua-core/src";

        rc = access(path, R_OK);

        if (rc == 0)
        {
            strcpy(cfg.lua.system_path, path);
        }
    }

    if (lua_user_path)
    {
        strcpy(cfg.lua.user_path, lua_user_path);
    }
	/*host = (as_config_host*)palloc0(sizeof(as_config_host));
	host->addr = as_config_add_host;
	host->port = as_server_port;
	*/
        aerospike_init(p_as, &cfg);
	p_as->config.hosts[0].addr = as_server_ip;
	p_as->config.hosts[0].port = as_server_port;

        if (aerospike_connect(p_as, &err) != AEROSPIKE_OK)
        {
                elog(LOG,"connect aerospike server failed\r\n %d - %s", err.code, err.message);
                exit(-1);
        }
}

void _PG_init(void){
	aerospike_fdw_init();

        elog(LOG,"start connect as server\n");
	DefineCustomStringVariable("aerospike.as_server_ip",
                        "aerospike ip address.",
                        NULL,
                        &as_server_ip,
                        "127.0.0.1",
                        PGC_POSTMASTER,
                        0,
                        NULL,
                        NULL,
                        NULL);
        elog(LOG,"--->as_server_ip:%s\n",as_server_ip);
        DefineCustomIntVariable("aerospike.as_server_port",
                        "aerospike port",
                        NULL,
                        &as_server_port,
                        3000,
                        1,
                        INT_MAX,
                        PGC_POSTMASTER,
                        0,
                        NULL,
                        NULL,
                        NULL);
	elog(LOG,"--->as_server_port:%d\n",as_server_ip);
        Connect_to_aerospike_with_udf_configtmp(&as_ip2location, as_server_ip, as_server_port, NULL);

}

static bool insert_as_record(Oid foreignTableId,
                             Oid *att_type,
                             Datum *values,
                             char **attr_name,
                             int cloumn,
                             bool *columnNulls)
{
    int i;
    as_error err;
    as_key key_rec;
    as_record as_rec;
    AerospikeFdwOptions *op_val = NULL;
    op_val = AerospikeGetOptions(foreignTableId);
	text* t;
	char *temp;
    char *val;
    Oid             typoutputfunc;
    bool            typIsVarlena;
	//as_hashmap map;
	//as_hashmap_init(&map, cloumn);
	as_record_init(&as_rec, cloumn);
    for(i = 0; i < cloumn; i++)
    {
        if(strcmp(op_val->column_key, attr_name[i])==0)
        {
             switch (att_type[i])
             {
				case 16:/*bool*/
				{
					as_key_init_int64(&key_rec,
							op_val->as_namespace,
							op_val->as_set,
							(int64_t)DatumGetBool(values[i]));
					break;
				}
				case 17:/*bytea*/
                case 25:/* text */
                case 700 :/*float4*/
                case 701 :/*float8*/
                case 1043 :/*varchar*/
				{
                    getTypeOutputInfo(att_type[i], &typoutputfunc, &typIsVarlena);
                    val  =  DatumGetCString(OidFunctionCall1(typoutputfunc, values[i]));
					as_key_init_str(&key_rec, op_val->as_namespace, op_val->as_set, val);
					break;
				}
				case 20:/* Int64 */
				{
					as_key_init_int64(&key_rec,
							op_val->as_namespace,
							op_val->as_set,
							(int64_t)DatumGetInt64(values[i]));
					break;
				}
				case 21:/* Int16 */
				{
					as_key_init_int64(&key_rec,
							op_val->as_namespace,
							op_val->as_set,
							(int64_t)DatumGetInt16(values[i]));
					break;
				}
				case 23:/* Int32 */
				{
					as_key_init_int64(&key_rec,
							op_val->as_namespace,
							op_val->as_set,
							(int64_t)DatumGetInt32(values[i]));
					break;
				}
				case 1184 :/*timestamptz*/
				{
					as_key_init_int64(&key_rec,
							op_val->as_namespace,
							op_val->as_set,
							DatumGetTimestamp(values[i]));
					break;
				}

			}
		}
		switch (att_type[i])
		{
			case 16:/*bool*/
			{
                bool t16;
                t16 = DatumGetBool(values[i]);
				as_record_set_int64(&as_rec, attr_name[i], (int64_t)DatumGetBool(values[i]));
				break;
			}
			case 20:
			{
				as_record_set_int64(&as_rec, attr_name[i], DatumGetInt64(values[i]));
				break;
			}
			case 21:
			{
				as_record_set_int64(&as_rec, attr_name[i], DatumGetInt16(values[i]));
				break;
			}
			case 23:
			{
				as_record_set_int64(&as_rec, attr_name[i], DatumGetInt32(values[i]));
				break;
			}
			case 700 :/*float4*/
			{
                float t700;
                t700 = DatumGetFloat4(values[i]);
				as_record_set_double(&as_rec, attr_name[i], DatumGetFloat4(values[i]));
				break;
			}
			case 701 :/*float8*/
			{
                float t701 = DatumGetFloat8(values[i]);
				as_record_set_double(&as_rec, attr_name[i], DatumGetFloat8(values[i]));
				break;
			}
            case 17:/*bytea*/
            case 25:/* text */
            case 1043 :/*varchar*/
			{
                getTypeOutputInfo(att_type[i], &typoutputfunc, &typIsVarlena);
                val  =  DatumGetCString(OidFunctionCall1(typoutputfunc, values[i]));
				as_record_set_str(&as_rec, attr_name[i], val);
				break;
			}
			case 1184 :/*timestamptz*/
            {
                as_record_set_int64(&as_rec, attr_name[i], DatumGetTimestamp(values[i]));
                break;
            }
			default:
				break;
		}
	}

    if(aerospike_key_put(&as_ip2location, &err, NULL, &key_rec, &as_rec)!=AEROSPIKE_OK)
	{
		as_record_destroy(&as_rec);
        printf("aerospike_key_put() returned %d - %s", err.code, err.message);
        return false;
    }
	as_record_destroy(&as_rec);

    return true;
}

static char *AerospikeGetOptionValue(Oid foreignTableId, const char *optionName)
{
    ForeignTable *foreignTable = NULL;
    ForeignServer *foreignServer = NULL;
    List *optionList = NIL;
    ListCell *optionCell = NULL;
    char *optionValue = NULL;

    foreignTable = GetForeignTable(foreignTableId);
    foreignServer = GetForeignServer(foreignTable->serverid);

    optionList = list_concat(optionList, foreignTable->options);
    optionList = list_concat(optionList, foreignServer->options);

    foreach(optionCell, optionList)
    {
        DefElem *optionDef = (DefElem *) lfirst(optionCell);
        char *optionDefName = optionDef->defname;

        if (strncmp(optionDefName, optionName, NAMEDATALEN) == 0)
        {
            optionValue = defGetString(optionDef);
            break;
        }
    }

    return optionValue;
}

static AerospikeFdwOptions *AerospikeGetOptions(Oid foreignTableId)
{
    AerospikeFdwOptions *Options = NULL;
    char *as_namespace = NULL;
    char *as_set = NULL;
    char *column_key = NULL;

    as_namespace = AerospikeGetOptionValue(foreignTableId, OPTION_NAME_SPACE);
    as_set = AerospikeGetOptionValue(foreignTableId, OPTION_SET);
    column_key = AerospikeGetOptionValue(foreignTableId, OPTION_KEY);

	/* FIXME: check option list is valid */
    Options = (AerospikeFdwOptions *)palloc0(sizeof(AerospikeFdwOptions));
	Options->as_namespace = palloc0(strlen(as_namespace) + 1);
    memcpy(Options->as_namespace, as_namespace, strlen(as_namespace));
	Options->as_set = palloc0(strlen(as_set) + 1);
    memcpy(Options->as_set, as_set, strlen(as_set));
	Options->column_key = palloc0(strlen(column_key) + 1);
    memcpy(Options->column_key, column_key, strlen(column_key));

    return Options;
}

static StringInfo OptionNamesString(Oid currentContextId)
{
    StringInfo optionNamesString = makeStringInfo();
    bool firstOptionAppended = false;

    int32 optionIndex = 0;
    for (optionIndex = 0; optionIndex < ValidOptionCount; optionIndex++)
    {
        const AerospikeValidOption *validOption = &(ValidOptionArray[optionIndex]);

        /* if option belongs to current context, append option name */
        if (currentContextId == validOption->optionContextId)
        {
            if (firstOptionAppended)
            {
                appendStringInfoString(optionNamesString, ", ");
            }

            appendStringInfoString(optionNamesString, validOption->optionName);
            firstOptionAppended = true;
        }
    }

	return optionNamesString;
}

static TupleTableSlot *aerospike_form_tupletableslot(int listlen, Oid tableid,
												 const as_val *as_map_val, TupleDesc tupleDescriptor)
{
    int i = 1;
    ListCell *list_tmp;
    Var *var;
	TupleDesc desc;
	Datum *values_get;
	bool*  nulls;
	HeapTuple tuple_get;
	TupleTableSlot *slot_tmp;
	TupleTableSlot *slot;

    desc = CreateTemplateTupleDesc(listlen, false);
	values_get = (Datum*)palloc0(sizeof(Datum) * listlen);
	nulls = (bool*)palloc0(sizeof(bool) * listlen);

	Relation rd;
	rd = RelationIdGetRelation(tableid);

    for (i = 1; i <= listlen; i++)
    {
        Oid oidtypeid;
        Node *nodevar;
    	as_string name_tmp;
        as_val *p_ret_val = NULL;
        int str_len;
        char *buf;

		char *column_name = NULL;
	    column_name = RIAttName(rd, i);
		oidtypeid = tupleDescriptor->attrs[i - 1]->atttypid;

		TupleDescInitEntry(desc, (AttrNumber) i, column_name, oidtypeid, -1, 0);
		as_string_init(&name_tmp, column_name, false);
		p_ret_val = as_map_get((as_map *)as_map_val, (const as_val *)&name_tmp);
		if (p_ret_val == NULL)
		{
			values_get[i - 1] = NULL;
			nulls[i - 1] = true;
			continue;
		}

		if (p_ret_val->type == AS_NIL)
		{
			values_get[i - 1] = NULL;
			nulls[i - 1] = true;
		}
		else
		{
			/*
			   AS_UNKNOWN      = 0,	//<! @deprecated
			   AS_NIL          = 1,
			   AS_BOOLEAN      = 2,
			   AS_INTEGER      = 3,
			   AS_STRING       = 4,
			   AS_LIST         = 5,
			   AS_MAP          = 6,
			   AS_REC          = 7,
			   AS_PAIR         = 8,
			   AS_BYTES        = 9,
			   */
			switch(p_ret_val->type)
			{
				case AS_INTEGER:
	            {
                    if ((oidtypeid == 700) || (oidtypeid == 701))
                    {
                        double tmp;
                        tmp = as_double_get((as_double *)p_ret_val);
                        values_get[i - 1] = Float8GetDatum((float8)tmp);
                    }
                    else if (oidtypeid == 1184)
                    {
                        int64_t num = as_integer_get((as_integer *)p_ret_val);
                        values_get[i - 1] = TimestampGetDatum(num);
                    }
                    else
                    {
					    int64_t num = as_integer_get((as_integer *)p_ret_val);
					    values_get[i - 1] = Int64GetDatum(num);
                    }
					break;
				}
				case AS_STRING:
	            {
                    Oid             typinputfunc;
                    Oid             typioparam;

					char *temp = as_string_get((as_string *)p_ret_val);
					str_len = strlen(temp);
					buf = (char *)palloc(str_len + 1);
					memcpy(buf, temp, str_len);
					buf[str_len] = '\0';
                    getTypeInputInfo(oidtypeid, &typinputfunc, &typioparam);
					values_get[i - 1] = CStringGetDatum(OidInputFunctionCall(typinputfunc, buf, typioparam, -1));
					break;
				}
				case AS_DOUBLE:
                {
                    double tmp;
                    tmp = as_double_get((as_double *)p_ret_val);
                    values_get[i - 1] = Float8GetDatum((float8)tmp);
					break;
				}
				case AS_BOOLEAN:
				{
					bool value = as_boolean_get((as_boolean*)p_ret_val);
					values_get[i - 1] = BoolGetDatum(value);
					break;
				}
				case AS_LIST:
				{
                    Oid             typinputfunc;
                    Oid             typioparam;
                    getTypeInputInfo(oidtypeid, &typinputfunc, &typioparam);
					as_map *tmp_map;
					tmp_map = as_arraylist_get_map((as_arraylist *)p_ret_val, 1);
					char* p_str = as_val_tostring(tmp_map);
					values_get[i - 1] = JsonbGetDatum(OidInputFunctionCall(typinputfunc, p_str, typioparam, -1));
				}
					break;
				case AS_MAP:
				{
                    Oid             typinputfunc;
                    Oid             typioparam;
                    getTypeInputInfo(oidtypeid, &typinputfunc, &typioparam);

					char* p_str = as_val_tostring(p_ret_val);
					values_get[i - 1] = JsonbGetDatum(OidInputFunctionCall(typinputfunc, p_str, typioparam, -1));
					break;
				}
				case AS_REC:
					break;
				default:
					break;

			}
			nulls[i - 1] = false;
		}
    }
	RelationClose(rd);
    tuple_get = heap_form_tuple(desc, values_get, nulls);
    slot_tmp = MakeSingleTupleTableSlot(desc);
    slot = ExecStoreTuple(tuple_get, slot_tmp, InvalidBuffer, false);

    return slot;
}

compile_result *as_compileudf_file(List *whereColumnList, List *targetList, int listlen, char *clausestr, Oid Foreignid)
{
	int i = 1;
	int fd_udf_lua;
	int ret;
	time_t t;
	char buff[128] = {0};
	char timestr[64] = {0};
	char filename[64] = {0};
	char *str_tmp;
	int size;
	char *column_name;
	compile_result *p_compile_result;

    uint8_t* content = (uint8_t*)palloc0(1024 * 1024);
    if (! content)
	{
        elog(LOG,"script content allocation failed");
        return NULL;
    }
    memset(content, 0, 1024*1024);
    uint8_t* p_write = content;

	time(&t);
	sprintf(timestr,"%d_%ld",Foreignid, t);
	sprintf(filename,"%d_%ld.lua",Foreignid, t);

	p_compile_result = palloc0(sizeof(compile_result));
    if (NULL == p_compile_result)
    {
    	return NULL;
    }

    char *udf_func_name = NULL;
    char *udf_module_name = NULL;
    udf_func_name = (char *)palloc0(strlen("udf_func_entry")+1);
    if (!udf_func_name)
    {
        pfree(p_compile_result);
        p_compile_result = NULL;
        return p_compile_result;
    }

    udf_module_name = (char *)palloc0(strlen(timestr)+1);
    if (!udf_module_name)
    {
        pfree(udf_func_name);
        udf_func_name = NULL;
        pfree(p_compile_result);
        p_compile_result = NULL;
        return p_compile_result;
    }

    p_compile_result->udf_func_name = udf_func_name;
    p_compile_result->udf_module_name = udf_module_name;

    //memcpy(p_compile_result->udf_func_name, timestr, strlen(timestr));
    memcpy(p_compile_result->udf_func_name, "udf_func_entry", strlen("udf_func_entry"));
    memcpy(p_compile_result->udf_module_name, timestr, strlen(timestr));

    memcpy((char *)p_write, "local function udf_return_fun(rec)\n",strlen("local function udf_return_fun(rec)\n"));

    strcat((char *)p_write, "\tret = map()\n");
	Relation rd;
	rd = RelationIdGetRelation(Foreignid);

	ListCell   *j;
	foreach(j, targetList)
	{
		Node *col = (Node *) lfirst(j);
	    column_name = RIAttName(rd, ((Var *)col)->varattno);

		sprintf(buff, "\tret.%s = rec.%s\n",column_name, column_name);
		strcat((char *)p_write, buff);
		memset(buff, 0, 128);
	}

    strcat((char *)p_write, "\treturn ret\n");
    strcat((char *)p_write, "end\n");
    //sprintf(buff, "function %s(stream)\n", timestr);
	//strcat((char *)p_write, buff);
	strcat((char *)p_write,  "function udf_func_entry(stream)\n");
    strcat((char *)p_write, "\tlocal function filter_fun(rec)\n");

	if (list_length(whereColumnList) != 0)
	{
		strcat((char *)p_write, "\t\tif ");

		foreach(j, whereColumnList)
		{
			Node *col = (Node *) lfirst(j);
		    column_name = RIAttName(rd, ((Var *)col)->varattno);
			if (i != list_length(whereColumnList))
			{
				sprintf(buff, "rec.%s==nil or ",column_name);
			}
			else
			{
				sprintf(buff, "rec.%s==nil then\n",column_name);
			}
			strcat((char *)p_write, buff);
			memset(buff, 0, 128);
			i++;
		}
		strcat((char *)p_write, "\t\t\treturn false\n\t\telse\n");
	}
    if(clausestr)
    {
        memset(buff, 0, 128);
	    sprintf(buff, "\t\t\treturn %s\n", clausestr);
        strcat((char *)p_write, buff);
    }
	else
	{
	    sprintf(buff, "\t\t\treturn true\n");
        strcat((char *)p_write, buff);
	}

	if (list_length(whereColumnList) != 0)
	{
		strcat((char *)p_write, "\t\tend\n");
	}
    strcat((char *)p_write, "\tend\n");
    strcat((char *)p_write, "\treturn stream : filter(filter_fun) : map(udf_return_fun)\n");
    strcat((char *)p_write, "end\n");
    size = strlen((char *)content);
    RelationClose(rd);

#if 1
    memset(buff, 0, 128);
	sprintf(buff, "/home/pg/lua/%d_%ld.lua",Foreignid, t);
    fd_udf_lua = open(buff, O_RDWR|O_CREAT|O_TRUNC, 0644);
    if(write(fd_udf_lua, p_write, size)<0)
    {
        perror("open file failed");
    }
    close(fd_udf_lua);
#endif
    // Wrap the local buffer as an as_bytes object.
    as_bytes udf_content;
    as_bytes_init_wrap(&udf_content, content, size, false);
    as_error err;
    as_string base_string;
    const char* base = as_basename(&base_string, filename);
    // Register the UDF file in the database cluster.
    if (aerospike_udf_put(&as_ip2location, &err, NULL, base, AS_UDF_TYPE_LUA,
    &udf_content) == AEROSPIKE_OK) {
    // Wait for the system metadata to spread to all nodes.
    aerospike_udf_put_wait(&as_ip2location, &err, NULL, base, 100);
    }
    else {
        elog(LOG,"aerospike_udf_put() returned %d - %s", err.code, err.message);
    }

	pfree(content);
    as_string_destroy(&base_string);
    // This frees the local buffer.
    as_bytes_destroy(&udf_content);
    err.code == AEROSPIKE_OK;

    return p_compile_result;

}

bool remove_udf_module(aerospike* p_as, const char* udf_file_path)
{
	as_error err;
	as_string base_string;
	const char* base = as_basename(&base_string, udf_file_path);
	if (aerospike_udf_remove(p_as, &err, NULL, base) != AEROSPIKE_OK) {
		elog(LOG,"aerospike_udf_remove() returned %d - %s", err.code, err.message);
		return false;
	}
	as_string_destroy(&base_string);
	// Wait for the system metadata to spread to all nodes.
	usleep(100 * 1000);
	return true;
}

Datum aerospike_fdw_handler(PG_FUNCTION_ARGS)
{
    FdwRoutine *fdwRoutine = makeNode(FdwRoutine);

    fdwRoutine->GetForeignRelSize = AsGetForeignRelSize;
    fdwRoutine->GetForeignPaths = AsGetForeignPaths;
    fdwRoutine->GetForeignPlan = AsGetForeignPlan;

    /* aerospike scan function */
    fdwRoutine->BeginForeignScan = BeginScanAsRelation;
    fdwRoutine->IterateForeignScan = AsScanNext;
    fdwRoutine->EndForeignScan = EndScanAsRelation;

    /* aerospike insert function */
    fdwRoutine->PlanForeignModify = AsPlanForeignModify;
    fdwRoutine->BeginForeignModify = AsBeginForeignModify;
    fdwRoutine->ExecForeignInsert = AsExecForeignInsert;
    fdwRoutine->EndForeignModify = AsEndForeignModify;

    PG_RETURN_POINTER(fdwRoutine);
}

Datum aerospike_fdw_validator(PG_FUNCTION_ARGS)
{
	Datum optionArray = PG_GETARG_DATUM(0);
	Oid optionContextId = PG_GETARG_OID(1);
	List *optionList = untransformRelOptions(optionArray);
	ListCell *optionCell = NULL;
	char *as_namespace = NULL;
	char *as_set = NULL;
	char *column_key = NULL;

	foreach(optionCell, optionList)
	{
		DefElem *optionDef = (DefElem *) lfirst(optionCell);
		char *optionName = optionDef->defname;
		bool optionValid = false;

		int32 optionIndex = 0;
		for (optionIndex = 0; optionIndex < ValidOptionCount; optionIndex++)
		{
	        const AerospikeValidOption *validOption = &(ValidOptionArray[optionIndex]);

	        if ((optionContextId == validOption->optionContextId)
	                        && (strncmp(optionName, validOption->optionName, NAMEDATALEN) == 0))
	        {
                optionValid = true;
                break;
	        }
		}

		/* if invalid option, display an informative error message */
		if (!optionValid)
		{
	        StringInfo optionNamesString = OptionNamesString(optionContextId);

	        ereport(ERROR,
                    (errcode(ERRCODE_FDW_INVALID_OPTION_NAME), errmsg("invalid option \"%s\"", optionName),
                    errhint("Valid options in this context are: %s", optionNamesString->data)));
		}

		if (strncmp(optionName, OPTION_NAME_SPACE, NAMEDATALEN) == 0)
		{
			as_namespace = defGetString(optionDef);
		}
		else if (strncmp(optionName, OPTION_SET, NAMEDATALEN) == 0)
		{
			as_set = defGetString(optionDef);
		}
		else if (strncmp(optionName, OPTION_SET, NAMEDATALEN) == 0)
		{
			column_key = defGetString(optionDef);
		}
	}

    if (optionContextId == ForeignTableRelationId)
    {
		/* FIXME: check option list is valid */
    }

    PG_RETURN_VOID() ;
}

static List *ColumnList(RelOptInfo *baserel)
{
    List *columnList = NIL;
    List *neededColumnList = NIL;
    AttrNumber columnIndex = 1;
    AttrNumber columnCount = baserel->max_attr;
    List *targetColumnList = baserel->reltargetlist;
    List *restrictInfoList = baserel->baserestrictinfo;
    ListCell *restrictInfoCell = NULL;

    /* first add the columns used in joins and projections */
    neededColumnList = list_copy(targetColumnList);

    /* then walk over all restriction clauses, and pull up any used columns */
    foreach(restrictInfoCell, restrictInfoList)
    {
        RestrictInfo *restrictInfo = (RestrictInfo *) lfirst(restrictInfoCell);
        Node *restrictClause = (Node *) restrictInfo->clause;
        List *clauseColumnList = NIL;

        /* recursively pull up any columns used in the restriction clause */
        clauseColumnList = pull_var_clause(restrictClause, PVC_RECURSE_AGGREGATES,
                        PVC_RECURSE_PLACEHOLDERS);

        neededColumnList = list_union(neededColumnList, clauseColumnList);
    }
    /* walk over all column definitions, and de-duplicate column list */
    for (columnIndex = 1; columnIndex <= columnCount; columnIndex++)
    {
        ListCell *neededColumnCell = NULL;
        Var *column = NULL;

        /* look for this column in the needed column list */
        foreach(neededColumnCell, neededColumnList)
        {
            Var *neededColumn = (Var *) lfirst(neededColumnCell);
            if (neededColumn->varattno == columnIndex)
            {
                column = neededColumn;
                break;
            }
        }

        if (column != NULL)
        {
            columnList = lappend(columnList, column);
        }
    }

    return columnList;
}

static void AsGetForeignRelSize(PlannerInfo *root, RelOptInfo *baserel, Oid foreignTableId)
{
    return;
}

static void AsGetForeignPaths(PlannerInfo *root, RelOptInfo *baserel, Oid foreignTableId)
{
    Path *foreignScanPath = NULL;
#if 0
    OrcFdwOptions *options = OrcGetOptions(foreignTableId);

    BlockNumber pageCount = PageCount(options->filename);
    double tupleCount = TupleCount(baserel, options->filename);
#endif

    /*
     * We estimate costs almost the same way as cost_seqscan(), thus assuming
     * that I/O costs are equivalent to a regular table file of the same size.
     * However, we take per-tuple CPU costs as 10x of a seqscan to account for
     * the cost of parsing records.
     */
    double tupleParseCost = cpu_tuple_cost * AEROSPIKE_TUPLE_COST_MULTIPLIER;
    double tupleFilterCost = baserel->baserestrictcost.per_tuple;
    double cpuCostPerTuple = tupleParseCost + tupleFilterCost;
    //double executionCost = (seq_page_cost * pageCount) + (cpuCostPerTuple * tupleCount);

    double startupCost = baserel->baserestrictcost.startup;
    //double totalCost = startupCost + executionCost;

    /* create a foreign path node and add it as the only possible path */
    foreignScanPath = (Path *) create_foreignscan_path(root, baserel, baserel->rows, startupCost,
                    startupCost,
                    NIL, /* no known ordering */
                    NULL, /* not parameterized */
		    NULL,
                    NIL); /* no fdw_private */

    add_path(baserel, foreignScanPath);

    return;
}

static ForeignScan * AsGetForeignPlan(PlannerInfo *root, RelOptInfo *baserel, Oid foreignTableId,
                                      ForeignPath *bestPath, List *targetList, List *scanClauses,Plan *outer_plan)
{
    ForeignScan *foreignScan = NULL;
    List *columnList = NULL;
    List *foreignPrivateList = NIL;
    char *expr = NULL;
    List *remote_exprs = NIL;
    List *whereColumnList = NULL;
    /*
    * We have no native ability to evaluate restriction clauses, so we just
    * put all the scanClauses into the plan node's qual list for the executor
    * to check.
    */
    scanClauses = extract_actual_clauses(scanClauses, false);
    /*
    * As an optimization, we only add columns that are present in the query to
    * the column mapping hash. To find these columns, we need baserel. We don't
    * have access to baserel in executor's callback functions, so we get the
    * column list here and put it into foreign scan node's private list.
    */
    columnList = ColumnList(baserel);
	whereColumnList = pull_var_clause((Node *)scanClauses, PVC_RECURSE_AGGREGATES,PVC_REJECT_PLACEHOLDERS);
    if (scanClauses != NULL)
    {
        expr =  codegen_expr(NULL, linitial(scanClauses),foreignTableId);
    }
    g_compile_result = as_compileudf_file(whereColumnList, columnList, list_length(targetList), expr, foreignTableId);
    g_compile_result->listlen = list_length(targetList);
	g_compile_result->tableid = foreignTableId;

	foreignPrivateList = list_make1(columnList);

	/* create the foreign scan node */
	foreignScan = make_foreignscan(targetList,
			scanClauses,
			baserel->relid,
			NIL, /* no expressions to evaluate */
			foreignPrivateList,
			NIL,
			NIL,
			outer_plan);

    return foreignScan;
}

static void AsBeginForeignModify(ModifyTableState *modifyTableState,
                                 ResultRelInfo *relationInfo, List *fdwPrivate,
                                 int subplanIndex, int executorFlags)
{
	Oid  foreignTableOid = InvalidOid;
	TupleDesc tupleDescriptor = NULL;

	foreignTableOid = RelationGetRelid(relationInfo->ri_RelationDesc);

	relationInfo->ri_FdwState = (void *)(unsigned long)foreignTableOid;

	return;
}

static TupleTableSlot *AsExecForeignInsert(EState *executorState, ResultRelInfo *relationInfo,
                                           TupleTableSlot *tupleSlot, TupleTableSlot *planSlot)
{
	int i;
	char **att_name = NULL;
	Oid *att_type = NULL;
	Oid  foreignTableOid = InvalidOid;
	TupleDesc	tupleDescriptor;
	int column_count = 0;

    if(HeapTupleHasExternal(tupleSlot->tts_tuple))
    {
        /* detoast any toasted attributes */
        tupleSlot->tts_tuple = toast_flatten_tuple(tupleSlot->tts_tuple,
                tupleSlot->tts_tupleDescriptor);
    }

    slot_getallattrs(tupleSlot);

	tupleDescriptor = tupleSlot->tts_tupleDescriptor;
	foreignTableOid = (unsigned long) relationInfo->ri_FdwState;

	column_count = tupleDescriptor->natts;

	att_name = (char**)palloc0(column_count * sizeof(char*));
	att_type = palloc0(sizeof(Oid) * column_count);

	for (i = 0; i < column_count; i++)
	{
		att_name[i] = (char *)(tupleDescriptor->attrs[i]->attname.data);
		att_type[i] = tupleDescriptor->attrs[i]->atttypid;
	}

	insert_as_record(foreignTableOid, att_type,
                     tupleSlot->tts_values,
                     att_name,
                     column_count,
                     tupleSlot->tts_isnull);
	pfree(att_type);
	pfree(att_name);

	return NULL;
}
static void AsEndForeignModify(EState *executorState, ResultRelInfo *relationInfo)
{
    return;
}

static List *AsPlanForeignModify(PlannerInfo *plannerInfo, ModifyTable *plan,
                                 Index resultRelation, int subplanIndex)
{
    bool operationSupported = false;

    if (plan->operation == CMD_INSERT)
    {
        ListCell *tableCell = NULL;
        Query *query = NULL;

        /*
         *       * Only insert operation with select subquery is supported. Other forms
         *               * of insert, update, and delete operations are not supported.
         *                       */
        query = plannerInfo->parse;
        foreach(tableCell, query->rtable)
        {
            RangeTblEntry *tableEntry = lfirst(tableCell);

            if (tableEntry->rtekind == RTE_SUBQUERY &&
                    tableEntry->subquery != NULL &&
                    tableEntry->subquery->commandType == CMD_SELECT)
            {
                operationSupported = true;
                break;
            }
        }
    }

	#if 0
    if (!operationSupported)
    {
        ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                    errmsg("operation is not supported")));
    }
	#endif
    return NULL;
}

static bool as_query_cb(const as_val* p_val, void* udata)
{
	as_context *as_ctx = NULL;
    cf_queue *queue = NULL;
	as_ctx = (as_context *) udata;
    queue = as_ctx->context;
    TupleTableSlot *slot = NULL;

	if (queue == NULL)
	{
		return true;
	}

    if (! p_val)
    {
        slot = palloc0(sizeof(TupleTableSlot));
        ExecClearTuple(slot);
        cf_queue_push(queue, &slot);
        return true;
    }
    slot = aerospike_form_tupletableslot(g_compile_result->listlen,
									 g_compile_result->tableid,
                                     p_val,
                                     as_ctx->tupleDescriptor);

    cf_queue_push(queue, &slot);

    return true;
}

static void *As_thread_task(void *arg)
{
    as_error err;
    as_query query;
    cf_queue *queue = NULL;
	as_context *as_ctx = NULL;
	Oid foreignTableId;
	AerospikeFdwOptions *AerospikeFdwOptions = NULL;

	as_ctx = (as_context *) arg;
    queue = as_ctx->context;
	foreignTableId = as_ctx->foreignTableId;

	AerospikeFdwOptions = AerospikeGetOptions(foreignTableId);
	Connect_to_aerospike_with_udf_configtmp(&as, as_server_ip, as_server_port, "/home/pg/lua/");

    /*FIXME??*/
    as_query_init(&query, AerospikeFdwOptions->as_namespace, AerospikeFdwOptions->as_set);

    as_query_apply(&query, g_compile_result->udf_module_name, g_compile_result->udf_func_name, NULL);
    if (aerospike_query_foreach(&as, &err, NULL, &query, as_query_cb, (void *)as_ctx) !=
                    AEROSPIKE_OK)
    {
	    TupleTableSlot *slot = NULL;
        elog(LOG,"aerospike_query_foreach() returned %d - %s", err.code,
                    err.message);
        slot = palloc0(sizeof(TupleTableSlot));
        ExecClearTuple(slot);
        cf_queue_push(queue, &slot);
    }
}


static void BeginScanAsRelation(ForeignScanState *scanState, int executorFlags)
{
    int ret;
    pthread_t id;
    as_context *context;
	Oid foreignTableId = InvalidOid;
	TupleDesc	tupleDescriptor;

	foreignTableId = RelationGetRelid(scanState->ss.ss_currentRelation);
	tupleDescriptor = scanState->ss.ss_ScanTupleSlot ->tts_tupleDescriptor;

    context = palloc0(sizeof(as_context));

    context->context= cf_queue_create(sizeof(TupleTableSlot *), true);
	context->foreignTableId = foreignTableId;
	context->tupleDescriptor = tupleDescriptor;

    ret = pthread_create(&id, NULL, As_thread_task, (void*)context);

    context->id = id;
    scanState->fdw_state = (void *)context;

    return;
}

static TupleTableSlot *AsScanNext(ForeignScanState *scanState)
{
    as_context *context;
    TupleTableSlot *slot = NULL;
    TupleTableSlot *tupleSlot = scanState->ss.ss_ScanTupleSlot;

    context = (as_context *)scanState->fdw_state;

    ExecClearTuple(tupleSlot);

    cf_queue_pop(context->context, &slot, -1);

    if (slot->tts_isempty == true)
    {
        pthread_join(context->id, NULL);
        if (context->context)
        {
            cf_queue_destroy(context->context);
            context->context = NULL;
        }
    }
    else
    {
        ExecCopySlot(tupleSlot, slot);
    }

    return tupleSlot;
}

static void EndScanAsRelation(ForeignScanState *scanState)
{
	char filepath[256] = {0};
	as_error err;

    as_context *context = (as_context *)scanState->fdw_state;
    if ((context != NULL)&&(context->context != NULL))
    {
		pthread_join(context->id, NULL);
        if (context->context)
        {
	        cf_queue_destroy(context->context);
	        context->context = NULL;
        }
    }
    pfree(context);
    scanState->fdw_state = NULL;

    sprintf(filepath, "/home/pg/lua/%s.lua", g_compile_result->udf_module_name);
	remove_udf_module(&as_ip2location, filepath);
    pfree(g_compile_result->udf_func_name);
    pfree(g_compile_result->udf_module_name);
    pfree(g_compile_result);
	g_compile_result = NULL;
  	aerospike_close(&as, &err);
	aerospike_destroy(&as);

    return;
}


