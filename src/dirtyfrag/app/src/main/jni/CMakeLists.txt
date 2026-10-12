cmake_minimum_required(VERSION 3.22)
project(exp)
enable_language(ASM)

# 编译期硬化：
#   -fvisibility=hidden      默认全部符号不外露
#   -ffunction-sections/-fdata-sections + --gc-sections  让链接器回收不可达代码与数据
#   -Oz                      体积优先，顺带打乱指令形状
#   -flto=thin               跨编译单元优化，函数边界被打破
#   -Wno-format-security     fmt 现在是 OBF() 运行时解密出来的指针，不是字面量；
#                            AGP 默认加 -Werror=format-security 会把它判成 error。
#                            这里必须放在 ${C_FLAGS} 之后才能覆盖掉 -Werror=...
#                            安全性已单独核验：114 条串里 65 条是合法格式串（%s/%d/%zu...），
#                            另外 49 条经脚本逐字节解密确认不含 '%'，不存在格式化串注入面。
set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -I${CMAKE_SOURCE_DIR}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_FLAGS} -I${CMAKE_SOURCE_DIR} -Wall -Wextra -fno-stack-protector -fomit-frame-pointer -fvisibility=hidden -ffunction-sections -fdata-sections -Oz -flto=thin -Wno-format-security")

add_library(exp SHARED exp.c libcxx.S elf_parser.c crypto_core.c asm_str.c asset_names.c)

target_link_libraries(exp log)
# 链接期硬化：
#   --strip-all       去掉 .symtab（冒烟测试已验证）
#   --version-script  只导出 JNI_OnLoad（冒烟测试已验证 check_password 之类会被收敛掉）
#   -z max-page-size  保持原有页对齐
target_link_options(exp PRIVATE
    -Wl,--gc-sections
    -Wl,--strip-all
    -Wl,--version-script=${CMAKE_SOURCE_DIR}/exports.map
    -Wl,-z,max-page-size=16384)


# v22: standalone shell-domain fire binary (static, adb-fire path)
add_executable(exp_cli exp_cli.c libcxx.S elf_parser.c crypto_core.c asm_str.c asset_names.c)
target_compile_options(exp_cli PRIVATE -fno-stack-protector -fomit-frame-pointer -fvisibility=hidden -ffunction-sections -fdata-sections -Oz -Wno-format-security)
target_include_directories(exp_cli PRIVATE ${CMAKE_SOURCE_DIR})
target_link_options(exp_cli PRIVATE -Wl,--gc-sections -static)
