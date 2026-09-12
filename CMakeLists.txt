cmake_minimum_required(VERSION 3.16)
project(AuditForwarder
    VERSION 1.0.0
    DESCRIPTION "企业级跨平台安全审计 Agent"
    LANGUAGES CXX)

# -----------------------------------------------------------------------------
# 全局设置
# -----------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "构建类型" FORCE)
endif()

# 编译选项
if(MSVC)
    add_compile_options(/W4 /permissive- /utf-8 /Zc:__cplusplus)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00 WINVER=0x0A00)
else()
    add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-deprecated-declarations)
endif()

# -----------------------------------------------------------------------------
# 依赖库
# -----------------------------------------------------------------------------
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(Threads REQUIRED)
find_package(OpenSSL 1.1 REQUIRED)
find_package(ZLIB REQUIRED)

find_package(nlohmann_json 3.7 QUIET)
find_package(yaml-cpp QUIET)
find_package(spdlog QUIET)

include(CTest)
if(BUILD_TESTING)
    enable_testing()
    find_package(GTest QUIET)
endif()

# -----------------------------------------------------------------------------
# 平台相关配置
# -----------------------------------------------------------------------------
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(AF_PLATFORM_LINUX TRUE)
    add_compile_definitions(AF_PLATFORM_LINUX AF_PLATFORM_UNIX)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(AUDIT libaudit)
    if(AUDIT_FOUND)
        add_compile_definitions(AF_HAVE_LIBAUDIT)
    endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(AF_PLATFORM_WINDOWS TRUE)
    add_compile_definitions(AF_PLATFORM_WINDOWS _WIN32_WINNT=0x0A00 WINVER=0x0A00)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(AF_PLATFORM_DARWIN TRUE)
    add_compile_definitions(AF_PLATFORM_DARWIN AF_PLATFORM_UNIX)
endif()

# -----------------------------------------------------------------------------
# 收集核心源码，显式列出文件以便控制平台相关源码
# -----------------------------------------------------------------------------
set(AF_CORE_SOURCES
    # 通用模块
    shared/src/common/types.cpp
    shared/src/common/logger.cpp
    shared/src/common/config.cpp
    shared/src/common/config_parser.cpp
    shared/src/common/fs.cpp
    shared/src/common/thread_pool.cpp
    shared/src/common/process.cpp
    shared/src/common/event.cpp
    shared/src/database/database.cpp

    # 客户端核心模块
    client/src/core/agent.cpp
    client/src/core/remote_client.cpp
    client/src/core/self_protect.cpp

    # 密码学与证据链模块
    shared/src/crypto/crypto.cpp
    shared/src/crypto/chain.cpp

    # 事件处理模块
    client/src/processor/processor.cpp

    # 传输模块
    client/src/transport/https_transport.cpp

    # 违规检测模块
    shared/src/detector/rule_engine.cpp

    # 服务端管理模块
    server/src/manager/manager_server.cpp

    # 采集器基类
    client/src/collector/collector_base.cpp
)

if(AF_PLATFORM_LINUX)
    list(APPEND AF_CORE_SOURCES
        client/src/collector/linux/collectors_linux.cpp
        client/src/core/daemon_posix.cpp
    )
elseif(AF_PLATFORM_WINDOWS)
    list(APPEND AF_CORE_SOURCES
        client/src/collector/windows/collectors_win.cpp
        client/src/core/service_win.cpp
    )
else()
    list(APPEND AF_CORE_SOURCES
        client/src/collector/windows/collectors_win.cpp
        client/src/core/service_win.cpp
    )
    message(WARNING "未知平台，默认按 Windows 方式构建")
endif()

add_library(auditforwarder_core STATIC ${AF_CORE_SOURCES})

target_include_directories(auditforwarder_core
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/client/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/server/src"
        "${CMAKE_CURRENT_SOURCE_DIR}/shared/src"
)

target_link_libraries(auditforwarder_core
    PUBLIC
        Threads::Threads
        OpenSSL::SSL
        OpenSSL::Crypto
        ZLIB::ZLIB
)

if(yaml-cpp_FOUND)
    target_link_libraries(auditforwarder_core PUBLIC yaml-cpp)
    target_compile_definitions(auditforwarder_core PUBLIC AF_HAVE_YAML_CPP)
endif()

if(nlohmann_json_FOUND)
    target_link_libraries(auditforwarder_core PUBLIC nlohmann_json::nlohmann_json)
    target_compile_definitions(auditforwarder_core PUBLIC AF_HAVE_JSON)
endif()

if(spdlog_FOUND)
    target_link_libraries(auditforwarder_core PUBLIC spdlog::spdlog)
    target_compile_definitions(auditforwarder_core PUBLIC AF_HAVE_SPDLOG)
endif()

if(AF_PLATFORM_LINUX AND AUDIT_FOUND)
    target_link_libraries(auditforwarder_core PUBLIC ${AUDIT_LIBRARIES})
    target_include_directories(auditforwarder_core PUBLIC ${AUDIT_INCLUDE_DIRS})
endif()

if(AF_PLATFORM_WINDOWS)
    target_link_libraries(auditforwarder_core PUBLIC
        wevtapi advapi32 psapi iphlpapi ws2_32 user32 gdi32 shell32 tdh wtsapi32 userenv)
else()
    target_link_libraries(auditforwarder_core PUBLIC
        wevtapi advapi32 psapi iphlpapi ws2_32 user32 gdi32 shell32 tdh wtsapi32 userenv)
endif()

# -----------------------------------------------------------------------------
# 可执行程序
# -----------------------------------------------------------------------------
add_executable(auditforwarderd client/src/main.cpp)
target_link_libraries(auditforwarderd PRIVATE auditforwarder_core)

add_executable(auditforwarder-client client/src/client_main.cpp)
target_link_libraries(auditforwarder-client PRIVATE auditforwarder_core)

add_executable(auditforwarder-server server/src/server_main.cpp)
target_link_libraries(auditforwarder-server PRIVATE auditforwarder_core)

if(AF_PLATFORM_WINDOWS)
    set_target_properties(auditforwarderd PROPERTIES WIN32_EXECUTABLE TRUE)
    set_target_properties(auditforwarder-client PROPERTIES WIN32_EXECUTABLE TRUE)
    set_target_properties(auditforwarder-server PROPERTIES WIN32_EXECUTABLE TRUE)
endif()

install(TARGETS auditforwarderd auditforwarder-client auditforwarder-server
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

# -----------------------------------------------------------------------------
# 测试
# -----------------------------------------------------------------------------
if(BUILD_TESTING)
    file(GLOB AF_TESTS CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/*.cpp"
    )
    if(AF_TESTS)
        add_executable(auditforwarder_tests ${AF_TESTS})
        target_link_libraries(auditforwarder_tests
            PRIVATE
                auditforwarder_core
        )
        if(GTest_FOUND)
            target_link_libraries(auditforwarder_tests
                PRIVATE
                    GTest::gtest
                    GTest::gtest_main
            )
        endif()
        target_include_directories(auditforwarder_tests
            PRIVATE
                "${CMAKE_CURRENT_SOURCE_DIR}/include"
                "${CMAKE_CURRENT_SOURCE_DIR}/client/src"
                "${CMAKE_CURRENT_SOURCE_DIR}/server/src"
                "${CMAKE_CURRENT_SOURCE_DIR}/shared/src"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests"
        )
        add_test(NAME auditforwarder_tests COMMAND auditforwarder_tests)
    endif()
endif()

# -----------------------------------------------------------------------------
# 安装配置与脚本
# -----------------------------------------------------------------------------
install(DIRECTORY config/ DESTINATION etc/auditforwarder OPTIONAL)
install(DIRECTORY scripts/ DESTINATION share/auditforwarder/scripts USE_SOURCE_PERMISSIONS OPTIONAL)
install(DIRECTORY docs/ DESTINATION share/auditforwarder/docs OPTIONAL)
install(DIRECTORY server/web/ DESTINATION share/auditforwarder/web OPTIONAL)
