# Copyright (c) 2014 Percona LLC and/or its affiliates. All rights reserved.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA

option(ENABLE_AUDIT_MONGO "Build Audit Log with MongoDB C Driver" ON)

set (SOURCES audit_log.c file_logger.c buffer.c audit_file.c audit_syslog.c)

if (ENABLE_AUDIT_MONGO STREQUAL ON)
	
	find_path(MONGOC_INCLUDE_DIR
		NAMES libmongoc-1.0/mongoc.h
		PATHS /usr/include /usr/local/include
	)
	set(MONGOC_INCLUDE_DIR "${MONGOC_INCLUDE_DIR}/libmongoc-1.0")

	find_library(MONGOC_LIBRARY
		NAMES mongoc-1.0
		PATHS /usr /usr/local
		PATH_SUFFIXES lib lib64
	)

	find_path(BSON_INCLUDE_DIR
		NAMES libbson-1.0/bson.h
		PATHS /usr/include /usr/local/include
	)
	set(BSON_INCLUDE_DIR "${BSON_INCLUDE_DIR}/libbson-1.0")

	find_library(BSON_LIBRARY
		NAMES bson-1.0
		PATHS /usr /usr/local
		PATH_SUFFIXES lib lib64
	)
	
	INCLUDE_DIRECTORIES(${MONGOC_INCLUDE_DIR} ${BSON_INCLUDE_DIR})
	LINK_DIRECTORIES(${MONGOC_LIBRARY} ${BSON_LIBRARY})
	
	#TARGET_LINK_LIBRARIES(audit_log ${BSON_LIBRARY})
	
	add_definitions(-DAUDIT_HAVE_MONGO)
	
	set(SOURCES ${SOURCES} audit_mongo.c)
	set(LIBS ${MONGOC_LIBRARY} ${BSON_LIBRARY})
    
endif ()

MYSQL_ADD_PLUGIN(audit_log ${SOURCES} LINK_LIBRARIES ${LIBS} MODULE_ONLY MODULE_OUTPUT_NAME "audit_log")