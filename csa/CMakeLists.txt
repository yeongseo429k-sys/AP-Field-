cmake_minimum_required(VERSION 3.19)
project(csa-attack LANGUAGES CXX)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

qt_standard_project_setup()

qt_add_executable(csa-attack
    src/csa-attack.cpp
    include/radiotap.h src/radiotap.cpp
    include/dot11.h src/dot11.cpp
    include/mac.h src/mac.cpp
    include/param.h src/param.cpp
    include/pch.h
)

target_include_directories(csa-attack PRIVATE
    ${PCAP_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

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