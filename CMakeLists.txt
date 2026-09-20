cmake_minimum_required(VERSION 3.24)
project(2s_bbkpir LANGUAGES C CXX)

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
add_subdirectory("${SHKR_YAML_SOURCE}" "${CMAKE_BINARY_DIR}/yaml-cpp" EXCLUDE_FROM_ALL)

add_library(shkr_dpf STATIC
  "${SHKR_DPF_SOURCE}/AES.cpp"
  "${SHKR_DPF_SOURCE}/Defines.cpp"
  "${SHKR_DPF_SOURCE}/Log.cpp"
  "${SHKR_DPF_SOURCE}/PRNG.cpp"
  "${SHKR_DPF_SOURCE}/dpf.cpp")
target_include_directories(shkr_dpf PUBLIC "${SHKR_DPF_SOURCE}")
target_compile_options(shkr_dpf PRIVATE -O3 -march=native -DNDEBUG -Wno-ignored-attributes)

add_library(shkr_dpf_adapter STATIC src/payload/dpf_api.cpp)
target_include_directories(shkr_dpf_adapter PRIVATE src "${SHKR_DPF_SOURCE}")
target_compile_options(shkr_dpf_adapter PRIVATE -O3 -march=native -DNDEBUG -Wno-ignored-attributes)
target_link_libraries(shkr_dpf_adapter PUBLIC shkr_dpf)

add_library(shkr_crypto_compat STATIC src/crypto/blake2b.cpp)
target_compile_options(shkr_crypto_compat PRIVATE -O3 -march=native -DNDEBUG)

add_library(shkr_deps INTERFACE)
target_include_directories(shkr_deps INTERFACE src "${SHKR_JSON_SOURCE}/single_include")
target_include_directories(shkr_deps SYSTEM INTERFACE
  ${SHKR_YACL_INCLUDES}
  "${SHKR_PREFIX}/include"
  "${SHKR_GSL_SOURCE}/include"
  "${SHKR_APSI_SOURCE}/common"
  "${SHKR_COMPAT_INCLUDE}"
  "${SHKR_DPF_SOURCE}"
  "${SHKR_OT_SOURCE}/ot"
  "${SHKR_ENCRYPTO_GENERATED_INCLUDE}")
target_compile_definitions(shkr_deps INTERFACE
  HAVE_CONFIG USE_ENDO=true __LINUX__ _AMD64_ _AVX2_ _ASM_ SPDLOG_FMT_EXTERNAL)
target_compile_options(shkr_deps INTERFACE -O3 -march=native -DNDEBUG -Wno-deprecated-declarations)
target_link_libraries(shkr_deps INTERFACE
  yaml-cpp::yaml-cpp OpenMP::OpenMP_CXX Threads::Threads
  "${SHKR_FOURQ_ARCHIVE}" shkr_crypto_compat shkr_dpf_adapter
  "${SHKR_PREFIX}/lib/libotextension.a"
  "${SHKR_PREFIX}/lib/libencrypto_utils.a"
  "${SHKR_PREFIX}/lib/librelic_s.a"
  "${SHKR_PREFIX}/lib/libgmpxx.a"
  "${SHKR_PREFIX}/lib/libgmp.a"
  -lboost_system -lboost_thread "-Wl,@${SHKR_YACL_RSP}")
target_link_options(shkr_deps INTERFACE -fuse-ld=gold)

add_library(shkr_kk13_receiver OBJECT "${SHKR_OT_SOURCE}/ot/kk-ot-ext-rec.cpp")
target_include_directories(shkr_kk13_receiver PRIVATE
  "${SHKR_PREFIX}/include" "${SHKR_ENCRYPTO_GENERATED_INCLUDE}")
target_compile_options(shkr_kk13_receiver PRIVATE -O3 -march=native -DNDEBUG)
target_link_libraries(shkr_deps INTERFACE $<TARGET_OBJECTS:shkr_kk13_receiver>)

add_executable(shkr_preprocess src/preprocess/main.cpp)
target_link_libraries(shkr_preprocess PRIVATE shkr_deps)
add_executable(shkr_node src/shkr/node.cpp)
target_link_libraries(shkr_node PRIVATE shkr_deps)
add_executable(shkr_verify src/benchmark/verify.cpp)
target_link_libraries(shkr_verify PRIVATE shkr_deps)
