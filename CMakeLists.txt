cmake_minimum_required(VERSION 3.5)
project(driver-signer)

# set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-Wno-multichar -DUNICODE")
# set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-Wno-multichar -DUNICODE")

set(MINHOOK_SOURCES
    minhook/src/buffer.c
    minhook/src/hook.c
    minhook/src/trampoline.c
    minhook/src/hde/hde32.c
    minhook/src/hde/hde64.c
)

include_directories(minhook/include minhook/src minhook/src/hde)

add_library(minhook ${MINHOOK_SOURCES})

add_executable(driver-signer driver-signer.c)
target_link_libraries(driver-signer crypt32 cryptui shlwapi minhook)
