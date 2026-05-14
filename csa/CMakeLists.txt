cmake_minimum_required(VERSION 3.19)
project(csa-attack LANGUAGES CXX)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

qt_standard_project_setup()

qt_add_executable(csa-attack
    csa-attack.cpp
    radiotap.h radiotap.cpp
    dot11.h dot11.cpp
    mac.h mac.cpp
    param.h param.cpp
    pch.h
)

target_include_directories(csa-attack PRIVATE ${PCAP_INCLUDE_DIRS})

target_link_libraries(csa-attack
    PRIVATE
        Qt::Core
        ${PCAP_LIBRARIES}
)

install(TARGETS csa-attack
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)