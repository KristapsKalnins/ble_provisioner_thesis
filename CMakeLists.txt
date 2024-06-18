# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
set(QEMU_EXTRA_FLAGS -s)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(mesh_provisioner_test)

zephyr_include_directories(${ZEPHYR_BASE}/subsys/bluetooth/mesh)

target_sources(app PRIVATE src/main.c
                           src/rpr_test_client.c
                           src/lib/model/prov_helper_cli.c
                           src/lib/model/prov_helper_srv.c)

target_include_directories(app PRIVATE
  src/lib/model
)

if (CONFIG_BUILD_WITH_TFM)
  target_include_directories(app PRIVATE
    $<TARGET_PROPERTY:tfm,TFM_BINARY_DIR>/install/interface/include
  )
endif()
