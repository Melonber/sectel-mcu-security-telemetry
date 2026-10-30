cmake_minimum_required(VERSION 3.16)
# Semantic version used by the OTA anti-rollback check (MAJOR.MINOR.PATCH).
set(PROJECT_VER "0.3.1")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32_sectel)