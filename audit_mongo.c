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

#include <bson.h>
#include <bcon.h>
#include <mongoc.h>

typedef struct audit_handler_mongo_data_struct audit_handler_mongo_data_t;

struct audit_handler_mongo_data_struct
{
  size_t struct_size;
  
  mongoc_client_t *client;
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
	audit_handler_mongo_data_t *data;
	audit_handler_t *handler = (audit_handler_t*) calloc(sizeof(audit_handler_t) + sizeof(audit_handler_mongo_data_t), 1);
	if (handler != NULL)
	{
		// Initialize mongo client internals
		mongoc_init();
		
		// Init data struct and set info
		data = (audit_handler_mongo_data_t*) (handler + 1);
		data->struct_size = sizeof(audit_handler_mongo_data_t);
		data->footer = opts->footer;
		data->header = opts->header;
		
		// Create client instance
		data->client = mongoc_client_new(opts->uri);
		if (data->client == NULL)
		{
			mongoc_client_destroy(data->client);
			mongoc_cleanup();

			free(handler);
			handler= NULL;
		}
		else
		{
			// Set parameters for the mongo information
			data->collection = mongoc_client_get_collection (data->client, "percona", opts->collection);
			
			// Set parameters for the handler struct
			handler->data = data;
			handler->write = audit_handler_mongo_write;
			handler->flush = audit_handler_mongo_flush;
			handler->close = audit_handler_mongo_close;
		}
	}
	
	return handler;
}

static int audit_handler_mongo_write(audit_handler_t *handler, const char *buf, size_t len)
{
	audit_handler_mongo_data_t *data = (audit_handler_mongo_data_t*) handler->data;
	
	// Convert the *buf (JSON) string to BSON
	bson_error_t error;
	bson_t *bson = bson_new_from_json(buf, len, &error);
	if (!bson)
	{
		// Failed to parse JSON string
		fprintf(stderr, "Error parsing JSON: %s\n", error.message);
		return 0;
	}
	
	// Insert the "document"
	// TODO: Investigate MONGOC_INSERT_NO_VALIDATE
	// TODO: Investigate MONGOC_WRITE_CONCERN_W_UNACKNOWLEDGED
	if (!mongoc_collection_insert(data->collection, MONGOC_INSERT_NONE, bson, NULL, &error))
	{
		// Failed to add document
		fprintf(stderr, "Error parsing JSON: %s\n", error.message);
		return 0;
	}
	
	bson_destroy(bson);
	
	return len;
}

static int audit_handler_mongo_flush(audit_handler_t *handler)
{
	audit_handler_mongo_data_t *data = (audit_handler_mongo_data_t*) handler->data;
	bson_t *command = BCON_NEW("ping", BCON_INT32(1));
	bson_t reply;
	bson_error_t error;
	bool retval;
	
	retval = mongoc_client_command_simple(data->client, "admin", command, NULL, &reply, &error);
	if (!retval)
	{
		fprintf_timestamp(stderr);
		fprintf(stderr, "Error when flushing on 'ping' to mongo server.");
		perror("Error: ");
	}
	
	return 0;
}


int audit_handler_mongo_close(audit_handler_t *handler)
{
	audit_handler_mongo_data_t *data = (audit_handler_mongo_data_t*) handler->data;

	mongoc_collection_destroy(data->collection);
	mongoc_client_destroy(data->client);
	mongoc_cleanup();

	free(handler);

	return 0;
}