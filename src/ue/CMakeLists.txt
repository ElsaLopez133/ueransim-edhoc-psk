file(GLOB_RECURSE HDR_FILES *.hpp)
file(GLOB_RECURSE SRC_FILES *.cpp)

add_library(ue ${HDR_FILES} ${SRC_FILES})

target_compile_options(ue PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)
target_include_directories(ue PRIVATE /home/elsa/RustroverProjects/lakers/target/include)
target_link_libraries(ue
    PUBLIC
    common-lib
    /home/elsa/RustroverProjects/lakers/target/x86_64-unknown-linux-gnu/release/liblakers_c.a)
