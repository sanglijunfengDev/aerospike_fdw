#aerospike_fdw/Makefile

MODULE_big=aerospike_fdw
OBJS=aerospike_fdw.o luagen_builtins.o aerospike_planner.o  
AEROSPIKE_FDW_VERSION=1.0

EXTENSION= aerospike_fdw
DATA= aerospike_fdw--1.0.sql

LDFLAGS =-O0 -g  -lssl -lcrypto -lpthread -laerospike

CUSTOM_COPT =-O0 -g  -laerospike  -lcrypto -lpthread -I/usr/include 

PG_CONFIG= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)


distrib:
	rm -rf *.o
	rm -rf results/ regression.diffs regression.out tmp_check/ log/
	cd .. ; tar --exclude=.svn -chvzf aerospike_fdw-$(AEROSPIKE_FDW_VERSION).tar.gz aerospike_fdw
