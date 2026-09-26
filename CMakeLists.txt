cmake_minimum_required(VERSION 3.24)
project(pbkpir LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

if(NOT EXISTS "${CMAKE_BINARY_DIR}/deps.cmake")
  message(FATAL_ERROR "Run python3 scripts/configure_dependencies.py before CMake")
endif()
include("${CMAKE_BINARY_DIR}/deps.cmake")

find_package(Threads REQUIRED)
find_package(OpenMP REQUIRED)

set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(YAML_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
add_subdirectory("${SHKS_YAML_SOURCE}" "${CMAKE_BINARY_DIR}/yaml-cpp" EXCLUDE_FROM_ALL)

add_library(shks_dpf STATIC
  "${SHKS_DPF_SOURCE}/AES.cpp"
  "${SHKS_DPF_SOURCE}/Defines.cpp"
  "${SHKS_DPF_SOURCE}/Log.cpp"
  "${SHKS_DPF_SOURCE}/PRNG.cpp"
  "${SHKS_DPF_SOURCE}/dpf.cpp")
target_include_directories(shks_dpf PUBLIC "${SHKS_DPF_SOURCE}")
target_compile_options(shks_dpf PRIVATE -O3 -march=native -DNDEBUG -Wno-ignored-attributes)

add_library(shks_dpf_adapter STATIC src/payload/dpf_api.cpp)
target_include_directories(shks_dpf_adapter PRIVATE src "${SHKS_DPF_SOURCE}")
target_compile_options(shks_dpf_adapter PRIVATE -O3 -march=native -DNDEBUG -Wno-ignored-attributes)
target_link_libraries(shks_dpf_adapter PUBLIC shks_dpf)

add_library(shks_crypto_compat STATIC src/crypto/blake2b.cpp)
target_compile_options(shks_crypto_compat PRIVATE -O3 -march=native -DNDEBUG)

add_library(shks_deps INTERFACE)
target_include_directories(shks_deps INTERFACE src "${SHKS_JSON_SOURCE}/single_include")
target_include_directories(shks_deps SYSTEM INTERFACE
  ${SHKS_YACL_INCLUDES}
  "${SHKS_PREFIX}/include"
  "${SHKS_GSL_SOURCE}/include"
  "${SHKS_APSI_SOURCE}/common"
  "${SHKS_COMPAT_INCLUDE}"
  "${SHKS_DPF_SOURCE}"
  "${SHKS_OT_SOURCE}/ot"
  "${SHKS_ENCRYPTO_GENERATED_INCLUDE}")
target_compile_definitions(shks_deps INTERFACE
  HAVE_CONFIG USE_ENDO=true __LINUX__ _AMD64_ _AVX2_ _ASM_ SPDLOG_FMT_EXTERNAL)
target_compile_options(shks_deps INTERFACE -O3 -march=native -DNDEBUG -Wno-deprecated-declarations)
target_link_libraries(shks_deps INTERFACE
  yaml-cpp::yaml-cpp OpenMP::OpenMP_CXX Threads::Threads
  "${SHKS_FOURQ_ARCHIVE}" shks_crypto_compat shks_dpf_adapter
  "${SHKS_PREFIX}/lib/libotextension.a"
  "${SHKS_PREFIX}/lib/libencrypto_utils.a"
  "${SHKS_PREFIX}/lib/librelic_s.a"
  "${SHKS_PREFIX}/lib/libgmpxx.a"
  "${SHKS_PREFIX}/lib/libgmp.a"
  -lboost_system -lboost_thread "-Wl,@${SHKS_YACL_RSP}")
target_link_options(shks_deps INTERFACE -fuse-ld=gold)

add_library(shks_kk13_receiver OBJECT "${SHKS_OT_SOURCE}/ot/kk-ot-ext-rec.cpp")
target_include_directories(shks_kk13_receiver PRIVATE
  "${SHKS_PREFIX}/include" "${SHKS_ENCRYPTO_GENERATED_INCLUDE}")
target_compile_options(shks_kk13_receiver PRIVATE -O3 -march=native -DNDEBUG)
target_link_libraries(shks_deps INTERFACE $<TARGET_OBJECTS:shks_kk13_receiver>)

add_executable(shks_preprocess src/preprocess/main.cpp)
target_link_libraries(shks_preprocess PRIVATE shks_deps)
add_executable(shks_node src/shks/node.cpp)
target_link_libraries(shks_node PRIVATE shks_deps)
add_executable(shks_verify src/benchmark/verify.cpp)
target_link_libraries(shks_verify PRIVATE shks_deps)
