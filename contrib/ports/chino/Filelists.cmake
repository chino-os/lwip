# This file is indended to be included in end-user CMakeLists.txt
# include(/path/to/Filelists.cmake)
# It assumes the variable LWIP_CONTRIB_DIR is defined pointing to the
# root path of lwIP/contrib sources.
#
# This file is NOT designed (on purpose) to be used as cmake
# subdir via add_subdirectory()
# The intention is to provide greater flexibility to users to
# create their own targets using the *_SRCS variables.

if(NOT ${CMAKE_VERSION} VERSION_LESS "3.10.0")
    include_guard(GLOBAL)
endif()

set(lwipcontribportchino_SRCS
    ${LWIP_CONTRIB_DIR}/ports/chino/port/sys_arch.c
    ${LWIP_CONTRIB_DIR}/ports/chino/port/perf.c
)
set_source_files_properties(${lwipcontribportchino_SRCS} PROPERTIES LANGUAGE CXX)

set(lwipcontribportchinonetifs_SRCS
    ${LWIP_CONTRIB_DIR}/ports/chino/port/netif/tapif.c
    ${LWIP_CONTRIB_DIR}/ports/chino/port/netif/list.c
    ${LWIP_CONTRIB_DIR}/ports/chino/port/netif/sio.c
    ${LWIP_CONTRIB_DIR}/ports/chino/port/netif/fifo.c
)
set_source_files_properties(${lwipcontribportchinonetifs_SRCS} PROPERTIES LANGUAGE CXX)

add_library(lwipcontribportchino EXCLUDE_FROM_ALL ${lwipcontribportchino_SRCS} ${lwipcontribportchinonetifs_SRCS})
target_include_directories(lwipcontribportchino PRIVATE ${LWIP_INCLUDE_DIRS} ${LWIP_MBEDTLS_INCLUDE_DIRS})
target_compile_options(lwipcontribportchino PRIVATE ${LWIP_COMPILER_FLAGS})
target_compile_definitions(lwipcontribportchino PRIVATE ${LWIP_DEFINITIONS} ${LWIP_MBEDTLS_DEFINITIONS})
target_link_libraries(lwipcontribportchino PUBLIC ${LWIP_MBEDTLS_LINK_LIBRARIES})
