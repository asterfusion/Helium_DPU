cmake_minimum_required(VERSION 3.10)
project(poe_device_control)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -Werror")
set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_CXX_STANDARD 20)
set(SOURCES
    src/main.cc
    src/BtWorkSpace.cc
    src/PoeCommand.cc
    src/StructFormatter.cc
    src/Utils.cc
    src/LogMessage.cc
    src/LedCommand.cc
    src/UserInteraction.cc
    src/ExecBase.cc
)
add_executable(poe_device_control ${SOURCES})
install(TARGETS poe_device_control DESTINATION bin)