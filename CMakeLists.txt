cmake_minimum_required(VERSION 3.1)
project(des)

add_executable(des run_des.c des.c)
add_executable(mdes mem_des.c des.c)
add_executable(fdes file_des.c des.c)