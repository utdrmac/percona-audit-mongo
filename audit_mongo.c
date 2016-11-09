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

#include "audit_handler.h"
#include "log.h"

#include <bson.h>
#include <bcon.h>
#include <mongoc.h>

typedef struct audit_handler_mongo_data_struct audit_handler_mongo_data_t;

struct audit_handler_mongo_data_struct
{
  size_t struct_size;
  
  mongoc_client_t *client;
  mongoc_database_t *database;
  mongoc_collection_t *collection;
  
  logger_prolog_func_t header;
  logger_epilog_func_t footer;
};

static int audit_handler_mongo_write(audit_handler_t *handler, const char *buf, size_t len);
static int audit_handler_mongo_flush(audit_handler_t *handler);
static int audit_handler_mongo_flush(audit_handler_t *handler);
int audit_handler_mongo_close(audit_handler_t *handler);

audit_handler_t *audit_handler_mongo_open(audit_handler_mongo_config_t *opts)
{
	mongoc_uri_t *c_uri;
	audit_handler_mongo_data_t *data;
	audit_handler_t *handler;
	
	handler = (audit_handler_t*)calloc(sizeof(audit_handler_t) + sizeof(audit_handler_mongo_data_t), 1);
	if (handler != NULL)
	{
		// Initialize mongo client internals
		mongoc_init();
		sql_print_information("Audit_Mongo: Initialized mongoc\n");
		
		// Init data struct and set info
		data = (audit_handler_mongo_data_t*)(handler + 1);
		data->struct_size = sizeof(audit_handler_mongo_data_t);
		data->footer = opts->footer;
		data->header = opts->header;
		
		// Parse client-provided URI for errors
		c_uri = mongoc_uri_new(opts->uri);
		if (c_uri == NULL)
		{
			sql_print_error("Audit_Mongo: Failed to parse URI '%s'\n", opts->uri);
			goto error;
		}
		
		// Create client connection struct
		data->client = mongoc_client_new_from_uri(c_uri);
		if (data->client == NULL)
		{
			sql_print_error("Audit_Mongo: Failed to init mongo client '%s'\n", opts->uri);
			goto error;
		}
		else
		{
			// Get the database from the URI
			data->database = mongoc_uri_get_database(opts->uri);
			if (strlen(data->database) == 0)
			{
				sql_print_error("Audit_Mongo: No database specified in URI: '%s'\n", opts->uri);
				goto error;
			}
			
			// Set parameters for the mongo information
			data->collection = mongoc_client_get_collection(data->client, data->database, opts->collection);
			
			// Set parameters for the handler struct
			handler->data = data;
			handler->write = audit_handler_mongo_write;
			handler->flush = audit_handler_mongo_flush;
			handler->close = audit_handler_mongo_close;
			
			// All is good
			return handler;
		}
	}
	
error:
	if (data->collection)
		mongoc_collection_destroy(data->collection);
	
	if (data->database)
		mongoc_database_destroy(data->database);
	
	if (data->client)
		mongoc_client_destroy(data->client);
	
	mongoc_cleanup();
	
	data = NULL;
	
	free(c_uri);
	free(handler);
	
	c_uri = NULL;
	handler = NULL;
	
	return handler;
}

static int audit_handler_mongo_write(audit_handler_t *handler, const char *buf, size_t len)
{
	audit_handler_mongo_data_t *data = (audit_handler_mongo_data_t*)handler->data;
	size_t ret = len;
	
	bson_error_t error;
	bson_t *bson;
	
	// Convert the *buf (JSON) string to BSON
	bson = bson_new_from_json((uint8_t *)buf, ret, &error);
	if (!bson)
	{
		// Failed to parse JSON string
		sql_print_error("Audit_Mongo: Error parsing JSON: %s\n", error.message);
		sql_print_error("%s\n", buf);
		
		return 0;
	}
	
	// Insert the "document"
	// TODO: Investigate MONGOC_INSERT_NO_VALIDATE
	// TODO: Investigate MONGOC_WRITE_CONCERN_W_UNACKNOWLEDGED
	if (!mongoc_collection_insert(data->collection, MONGOC_INSERT_NONE, bson, NULL, &error))
	{
		// Failed to add document
		sql_print_error("Audit_Mongo: Error inserting JSON: %s\n", error.message);
		ret = 0;
	}
	
	bson_destroy(bson);
	
	return ret;
}

static int audit_handler_mongo_flush(audit_handler_t *handler)
{
	audit_handler_mongo_data_t *data = (audit_handler_mongo_data_t*)handler->data;
	bson_t *command = BCON_NEW("ping", BCON_INT32(1));
	
	bson_t reply;
	bson_error_t error;
	bool retval;
	
	retval = mongoc_client_command_simple(data->client, "admin", command, NULL, &reply, &error);
	if (!retval)
	{
		sql_print_error("Audit_Mongo: ping failure: %s\n", error.message);
	}
	
	return 0;
}


int audit_handler_mongo_close(audit_handler_t *handler)
{
	audit_handler_mongo_data_t *data = (audit_handler_mongo_data_t*)handler->data;
	
	mongoc_database_destroy(data->database);
	mongoc_collection_destroy(data->collection);
	mongoc_client_destroy(data->client);
	mongoc_cleanup();

	free(handler);
	
	sql_print_information("Audit_Mongo: Closed\n");
	
	return 0;
}