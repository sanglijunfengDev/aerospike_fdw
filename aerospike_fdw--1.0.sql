CREATE FUNCTION aerospike_fdw_handler()
RETURNS fdw_handler
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT;
 
CREATE FUNCTION aerospike_fdw_validator(text[], oid)
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT;

CREATE FOREIGN DATA WRAPPER aerospike_fdw
   HANDLER aerospike_fdw_handler
   VALIDATOR aerospike_fdw_validator;
