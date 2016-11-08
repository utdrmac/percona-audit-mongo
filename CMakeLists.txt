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

	find_path(BSON_INCLUDE_DIR
	  NAMES
		libbson-1.0/bson.h
		libbson-1.0/bcon.h
		libmongoc-1.0/mongoc.h
	  PATHS
	    /usr
	    /usr/local
	  PATH_SUFFIXES
		include
	)
	
	find_library(BSON_LIBRARY
      NAMES
        bson-1.0
        mongoc-1.0
      PATHS
        /usr
        /usr/local
      PATH_SUFFIXES
        lib
    )
	
	INCLUDE_DIRECTORIES(${BSON_INCLUDE_DIR})
	LINK_DIRECTORIES(${BSON_LIBRARY})
	
	TARGET_LINK_LIBRARIES(audit_log ${BSON_LIBRARY})
	
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DAUDIT_HAVE_MONGO")
	
    set(SOURCES ${SOURCES} audit_mongo.c)
    
endif ()

MYSQL_ADD_PLUGIN(audit_log ${SOURCES} MODULE_ONLY MODULE_OUTPUT_NAME "audit_log")