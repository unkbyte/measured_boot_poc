cmake_minimum_required(VERSION 3.31)
project(measured_boot_poc)

set(CMAKE_CXX_STANDARD 23)

add_executable(measured_boot_poc src/main.cpp)
target_link_options(measured_boot_poc PUBLIC -static-libstdc++)
target_compile_options(measured_boot_poc PUBLIC -fms-extensions)
target_link_libraries(measured_boot_poc PUBLIC Tbs.lib Wintrust.lib)
