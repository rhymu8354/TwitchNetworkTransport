# CMakeLists.txt for TwitchNetworkTransport
#
# © 2018 by Richard Walters

cmake_minimum_required(VERSION 3.8)
set(This TwitchNetworkTransport)

set(Headers
    include/TwitchNetworkTransport/Connection.hpp
)

set(Sources
    src/Connection.cpp
)

add_library(${This} STATIC ${Sources} ${Headers})
set_target_properties(${This} PROPERTIES
    FOLDER Libraries
)

target_include_directories(${This} PUBLIC include)

target_link_libraries(${This} PUBLIC
    SystemAbstractions
    TlsDecorator
    Twitch
)

add_subdirectory(test)
