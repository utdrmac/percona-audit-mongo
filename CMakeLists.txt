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

set (AUDIT_HAVE_MONGO 1)
set (SOURCES audit_log.c file_logger.c buffer.c audit_file.c audit_syslog.c)

if (ENABLE_AUDIT_MONGO STREQUAL ON)

	find_path(BSON_INCLUDE_DIR
	  NAMES
		libbson-1.0/bson.h
	  HINTS
		${BSON_ROOT_DIR}
		${_BSON_INCLUDEDIR}
	  PATH_SUFFIXES
		include
	)
	
	find_library(BSON_LIBRARY
      NAMES
        bson-1.0
      HINTS
        ${_BSON_LIBDIR}
      PATH_SUFFIXES
        lib
    )
	
	set(BSON_LIBRARIES ${BSON_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})
    set(LIBS ${LIBS} ${BSON_LIBRARIES})
    set(SOURCES ${SOURCES} audit_mongo.c)
    
endif ()

MYSQL_ADD_PLUGIN(audit_log ${SOURCES} MODULE_ONLY MODULE_OUTPUT_NAME "audit_log")