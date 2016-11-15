/* Copyright (c) 2016 Percona LLC and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; version 2 of
   the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA */

// TODO: Add counter of number of audit events
// TODO: Add logic if mongod goes away

#include "audit_handler.h"

#include <my_pthread.h>

#include <bson.h>
#include <bcon.h>
#include <mongoc.h>

typedef struct audit_handler_mongo_data_struct audit_handler_mongo_data_t;

struct audit_handler_mongo_data_struct
{
	size_t struct_size;
	
	mongoc_client_t *client;
	const char *database;
	mongoc_collection_t *collection;
	
	logger_prolog_func_t header;
	logger_epilog_func_t footer;
	
	mysql_mutex_t mutex;
};

/* For performance_schema */
#if defined(HAVE_PSI_INTERFACE)
static PSI_mutex_key audit_mongo_mutex;
static PSI_mutex_info mutex_key_list[]=
	{{ &audit_mongo_mutex, "audit_log_mongo::lock", PSI_FLAG_GLOBAL }};
#else
#define audit_mongo_mutex 0
#endif

int audit_handler_mongo_write(audit_handler_t *handler, const char *buf, size_t len);
int audit_handler_mongo_flush(audit_handler_t *handler);
int audit_handler_mongo_close(audit_handler_t *handler);

audit_handler_t *audit_handler_mongo_open(audit_handler_mongo_config_t *opts)
{
	mongoc_uri_t *c_uri;
	audit_handler_mongo_data_t *data;
	
	audit_handler_t *handler = (audit_handler_t*)calloc(sizeof(audit_handler_t) + sizeof(audit_handler_mongo_data_t), 1);
	if (handler == NULL)
	{
		fprintf_timestamp(stderr);
		fprintf(stderr, "Audit_Mongo: Failed to allocate handler\n");
		free(handler);
		handler = NULL;
		
		return NULL;
	}
	
	// Initialize mongo client internals
	mongoc_init();
	fprintf_timestamp(stderr);
	fprintf(stderr, "Audit_Mongo: Initialized mongoc\n");
	
	// Init data struct and set info
	data = (audit_handler_mongo_data_t*)(handler + 1);
	data->struct_size = sizeof(audit_handler_mongo_data_t);
	data->footer = opts->footer;
	data->header = opts->header;
	
	// Parse client-provided URI for errors
	c_uri = mongoc_uri_new(opts->uri);
	if (c_uri == NULL)
	{
		fprintf_timestamp(stderr);
		fprintf(stderr, "Audit_Mongo: Failed to parse URI '%s'\n", opts->uri);
	}
	else
	{
		// Create client connection struct
		data->client = mongoc_client_new_from_uri(c_uri);
		if (data->client == NULL)
		{
			fprintf_timestamp(stderr);
			fprintf(stderr, "Audit_Mongo: Failed to init mongo client '%s'\n", opts->uri);
		}
		else
		{
			// Get the database from the URI
			data->database = mongoc_uri_get_database(c_uri);
			if (strlen(data->database) == 0)
			{
				fprintf_timestamp(stderr);
				fprintf(stderr, "Audit_Mongo: No database specified in URI: '%s'\n", opts->uri);
			}
			else
			{
				// Set parameters for the mongo information
				data->collection = mongoc_client_get_collection(data->client, data->database, opts->collection);
				
				// Proper error reporting
				mongoc_client_set_error_api(data->client, MONGOC_ERROR_API_VERSION_2);
				
				// Mutex protection
#ifdef HAVE_PSI_INTERFACE
				if (PSI_server)
				{
					PSI_server->register_mutex("server_audit",
						mutex_key_list, array_elements(mutex_key_list));
				}
#endif
				mysql_mutex_init(audit_mongo_mutex, &data->mutex, MY_MUTEX_INIT_FAST);
				
				// Set parameters for the handler struct
				handler->data = data;
				handler->write = audit_handler_mongo_write;
				handler->flush = audit_handler_mongo_flush;
				handler->close = audit_handler_mongo_close;
				
				fprintf_timestamp(stderr);
				fprintf(stderr, "Audit_Mongo: Connected to '%s'\n", opts->uri);
				
				// All is good
				return handler;
			}
		}
	}
	
	// Some error happened above
	if (data->collection)
		mongoc_collection_destroy(data->collection);
	
	if (data->client)
		mongoc_client_destroy(data->client);
	
	mongoc_cleanup();
	
	data = NULL;
	
	free(c_uri);
	free(handler);
	
	c_uri = NULL;
	handler = NULL;
	
	return NULL;
}

int audit_handler_mongo_write(audit_handler_t *handler, const char *buf, size_t len)
{
	audit_handler_mongo_data_t *data = (audit_handler_mongo_data_t*)handler->data;
	
	bson_error_t error;
	bson_t *bson;
	
	// Protect Mongo business
	mysql_mutex_lock(&data->mutex);
	
	// Convert the *buf (JSON) string to BSON
	bson = bson_new_from_json((const uint8_t *)buf, -1, &error);
	if (!bson)
	{
		// Failed to parse JSON string
		fprintf_timestamp(stderr);
		fprintf(stderr, "Audit_Mongo: Error parsing JSON: %d.%d: %s\n",
			error.domain, error.code, error.message);
		fprintf(stderr, "Audit_Mongo: JSON: %s", buf);
		
		mysql_mutex_unlock(&data->mutex);
		
		return 0;
	}
	
	// Insert the "document"
	// TODO: Investigate MONGOC_INSERT_NO_VALIDATE
	// TODO: Investigate MONGOC_WRITE_CONCERN_W_UNACKNOWLEDGED
	if (!mongoc_collection_insert(data->collection, MONGOC_INSERT_NONE, bson, NULL, &error))
	{
		// Failed to add document
		fprintf_timestamp(stderr);
		fprintf(stderr, "Audit_Mongo: Error inserting JSON: %d.%d: %s\n",
			error.domain, error.code, error.message);
		
		fprintf_timestamp(stderr);
		fprintf(stderr, "Audit_Mongo: JSON: %s", buf);
	}
	
	bson_destroy(bson);
	
	mysql_mutex_unlock(&data->mutex);
	
	return len;
}

int audit_handler_mongo_flush(audit_handler_t *handler)
{
	audit_handler_mongo_data_t *data = (audit_handler_mongo_data_t*)handler->data;
	bson_t *command = BCON_NEW("ping", BCON_INT32(1));
	
	bson_t reply;
	bson_error_t error;
	bool retval;
	char *str;
	
	// Protect mongo business
	mysql_mutex_lock(&data->mutex);
	
	retval = mongoc_client_command_simple(data->client, "admin", command, NULL, &reply, &error);
	if (!retval)
	{
		fprintf_timestamp(stderr);
		fprintf(stderr, "Audit_Mongo: ping failure: %s\n", error.message);
		
		return 0;
	}
	
	str = bson_as_json(&reply, NULL);
	fprintf_timestamp(stderr);
	fprintf(stderr, "Audit_Mongo: Ping/Flush: %s\n", str);
	
	bson_free(str);
	bson_destroy(command);
	bson_destroy(&reply);
	
	mysql_mutex_unlock(&data->mutex);
	
	return 0;
}

static int audit_handler_mongo_close(audit_handler_t *handler)
{
	audit_handler_mongo_data_t *data = (audit_handler_mongo_data_t*)handler->data;
	
	mysql_mutex_destroy(&data->mutex);
	
	mongoc_collection_destroy(data->collection);
	mongoc_client_destroy(data->client);
	mongoc_cleanup();

	free(handler);
	
	fprintf_timestamp(stderr);
	fprintf(stderr, "Audit_Mongo: Connection Closed\n");
	
	return 0;
}

static void audit_log_mongo_flush_update(
	MYSQL_THD thd __attribute__((unused)),
	struct st_mysql_sys_var *var __attribute__((unused)),
	void *var_ptr __attribute__((unused)),
	const void *save)
{
	char new_val = *(const char *)(save);
	
	if (new_val != audit_log_flush && new_val)
	{
		audit_log_flush = TRUE;
		audit_log_mongo_reopen();
		audit_log_flush = FALSE;
	}
}

static int is_event_class_allowed_by_policy(unsigned int class, enum audit_log_policy_t policy)
{
	static unsigned int class_mask[] =
	{
		MYSQL_AUDIT_GENERAL_CLASSMASK | MYSQL_AUDIT_CONNECTION_CLASSMASK, /* ALL */
		0,                                                             /* NONE */
		MYSQL_AUDIT_CONNECTION_CLASSMASK,                              /* LOGINS */
		MYSQL_AUDIT_GENERAL_CLASSMASK,                                 /* QUERIES */
	};
	
	return (class_mask[policy] & (1 << class)) != 0;
}

static void audit_log_notify(MYSQL_THD thd __attribute__((unused)), unsigned int event_class, const void *event)
{
	char buf[1024];
	size_t len;

	if (!is_event_class_allowed_by_policy(event_class, audit_log_policy))
		return;

	if (event_class == MYSQL_AUDIT_GENERAL_CLASS)
	{
		const struct mysql_event_general *event_general = (const struct mysql_event_general *)event;
		switch (event_general->event_subclass)
		{
			case MYSQL_AUDIT_GENERAL_STATUS:
				if (event_general->general_command_length == 4 &&
					strncmp(event_general->general_command, "Quit", 4) == 0)
					break;
				
				len = audit_log_mongo_general_record(buf, sizeof(buf),
					event_general->general_command,
					event_general->general_time,
					event_general->general_error_code,
					event_general);
				
				audit_log_mongo_write(buf, len);
				
				break;
		}
	}
	else if (event_class == MYSQL_AUDIT_CONNECTION_CLASS)
	{
		const struct mysql_event_connection *event_connection = (const struct mysql_event_connection *)event;
		switch (event_connection->event_subclass)
		{
			case MYSQL_AUDIT_CONNECTION_CONNECT:
				len = audit_log_mongo_connection_record(buf, sizeof(buf),
					"Connect", time(NULL), event_connection);
				audit_log_mongo_write(buf, len);
				break;
			case MYSQL_AUDIT_CONNECTION_DISCONNECT:
				len = audit_log_mongo_connection_record(buf, sizeof(buf),
					"Quit", time(NULL), event_connection);
				audit_log_mongo_write(buf, len);
				break;
			case MYSQL_AUDIT_CONNECTION_CHANGE_USER:
				len = audit_log_mongo_connection_record(buf, sizeof(buf),
					"Change user", time(NULL), event_connection);
				audit_log_mongo_write(buf, len);
				break;
			default:
				break;
		}
	}
}

static const char *audit_log_mongo_policy_names[] = { "ALL", "NONE", "LOGINS", "QUERIES", 0 };

static TYPELIB audit_log_mongo_policy_typelib =
{
	array_elements(audit_log_mongo_policy_names) - 1, "audit_log_policy_typelib",
	audit_log_mongo_policy_names, NULL
};

static MYSQL_SYSVAR_ENUM(policy, audit_log_policy, PLUGIN_VAR_RQCMDARG,
	"The policy controlling the information written by the audit log "
	"plugin to its log file.", NULL, NULL, ALL,
	&audit_log_policy_typelib);

static MYSQL_SYSVAR_BOOL(flush, audit_log_flush,
	PLUGIN_VAR_OPCMDARG, "Close and reopen the connection.", NULL,
	audit_log_mongo_flush_update, 0);

// TODO: Support changing collection
static MYSQL_SYSVAR_STR(mongo_collection, audit_log_mongo_collection,
	PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,
	"The mongo collection to be used, if MONGODB handler is used.",
	NULL, NULL, default_audit_log_mongo_collection);

static MYSQL_SYSVAR_STR(mongo_uri, audit_log_mongo_uri,
	PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_MEMALLOC,
	"The URI of the mogo server to be used.",
	NULL, NULL, default_audit_log_mongo_uri);

static struct st_mysql_sys_var* audit_log_mongo_variables[] =
{
	MYSQL_SYSVAR(flush),
	MYSQL_SYSVAR(mongo_uri),
	MYSQL_SYSVAR(mongo_collection),
	NULL
};


/*
 * Plugin type-specific descriptor
 */
static struct st_mysql_audit audit_log_mongo_descriptor=
{
	MYSQL_AUDIT_INTERFACE_VERSION,                    /* interface version    */
	NULL,                                             /* release_thd function */
	audit_log_mongo_notify,                           /* notify function      */
	{ MYSQL_AUDIT_GENERAL_CLASSMASK |
		MYSQL_AUDIT_CONNECTION_CLASSMASK }              /* class mask           */
};

/*
 * Plugin status variables for SHOW STATUS
 */
static struct st_mysql_show_var audit_log_mongo_status_variables[]=
{
	{ 0, 0, 0}
};


/*
 * Plugin library descriptor
 */
mysql_declare_plugin(audit_log)
{
	MYSQL_AUDIT_PLUGIN,							/* type							   */
	&audit_log_mongo_descriptor,					/* descriptor					   */
	"audit_log_mongo",							/* name							   */
	"Percona LLC and/or its affiliates.",			/* author						   */
	"Audit log (Mongo)",							/* description					   */
	PLUGIN_LICENSE_GPL,
	audit_log_mongo_plugin_init,					/* init function (when loaded)	   */
	audit_log_mongo_plugin_deinit,				/* deinit function (when unloaded) */
	PLUGIN_VERSION,								/* version						   */
	audit_log_mongo_status_variables,				/* status variables				   */
	audit_log_mongo_system_variables,				/* system variables				   */
	NULL,
	0,
}
mysql_declare_plugin_end;