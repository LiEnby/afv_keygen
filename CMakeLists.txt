cmake_minimum_required(VERSION 3.12)

project(afv-keygen)

add_executable(${PROJECT_NAME} "")

target_sources(${PROJECT_NAME}
	PUBLIC
	${CMAKE_CURRENT_LIST_DIR}/main.c
 
 	${CMAKE_CURRENT_LIST_DIR}/crypto/aes.c   
 	${CMAKE_CURRENT_LIST_DIR}/crypto/aes_cbc.c
 	${CMAKE_CURRENT_LIST_DIR}/crypto/aes_cmac.c
 	${CMAKE_CURRENT_LIST_DIR}/crypto/aes.h
 	${CMAKE_CURRENT_LIST_DIR}/crypto/aes_cbc.h
 	${CMAKE_CURRENT_LIST_DIR}/crypto/aes_cmac.h    
)


target_include_directories(${PROJECT_NAME}
	PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}
)
