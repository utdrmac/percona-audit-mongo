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
  const char *database;
  mongoc_collection_t *collection;
  
  logger_prolog_func_t header;
  logger_epilog_func_t footer;
};

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
				
				// Set parameters for the handler struct
				handler->data = data;
				handler->write = audit_handler_mongo_write;
				handler->flush = audit_handler_mongo_flush;
				handler->close = audit_handler_mongo_close;
		
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
	
	// Convert the *buf (JSON) string to BSON
	bson = bson_new_from_json((const uint8_t *)buf, -1, &error);
	if (!bson)
	{
		// Failed to parse JSON string
		fprintf_timestamp(stderr);
		fprintf(stderr, "Audit_Mongo: Error parsing JSON: %d.%d: %s\n",
			error.domain, error.code, error.message);
		fprintf(stderr, "%s\n", buf);
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
		fprintf(stderr, "Audit_Mongo: JSON: %s\n", buf);
	}
	
	bson_destroy(bson);
	
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
	
	return 0;
}


int audit_handler_mongo_close(audit_handler_t *handler)
{
	audit_handler_mongo_data_t *data = (audit_handler_mongo_data_t*)handler->data;
	
	mongoc_collection_destroy(data->collection);
	mongoc_client_destroy(data->client);
	mongoc_cleanup();

	free(handler);
	
	fprintf_timestamp(stderr);
	fprintf(stderr, "Audit_Mongo: Closed\n");
	
	return 0;
}