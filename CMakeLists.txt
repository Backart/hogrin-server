cmake_minimum_required(VERSION 3.19)

project(Hogrin-Server LANGUAGES CXX)

find_package(Qt6 6.4 REQUIRED COMPONENTS Core Network Sql WebSockets)

qt_standard_project_setup()

# ── libsodium ─────────────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

qt_add_executable(Hogrin-Server
    main.cpp
    bootstrap_server.h
    bootstrap_server.cpp
    config.h
)

target_include_directories(Hogrin-Server PRIVATE ${SODIUM_INCLUDE_DIRS})

target_link_libraries(Hogrin-Server
    PRIVATE
        Qt6::Core
        Qt6::Network
        Qt6::Sql
        Qt6::WebSockets
        ${SODIUM_LIBRARIES}
)

include(GNUInstallDirs)

install(TARGETS Hogrin-Server
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
