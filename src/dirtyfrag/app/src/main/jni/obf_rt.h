/* 源码层混淆原语（手写，替代 O-MVLL 的 pass） */
#pragma once
#include <stdint.h>

/* ---- 不透明谓词：结果经内联汇编产出，编译器无法折叠分支 ---- */
static volatile uint32_t _obf_seed = 0x9e3779b9u;
static inline uint32_t _opaque_u32(uint32_t x) {
    uint32_t r;
    __asm__ volatile("mov %w0, %w1" : "=r"(r) : "r"(x));
    return r;
}
#define OPAQUE_T()  ((_opaque_u32(0x9e37u) | 1u) != 0u)   /* 恒真 */
#define OPAQUE_F()  ((_opaque_u32(0x9e37u) & 0u) != 0u)   /* 恒假 */

/* ---- MBA 混合布尔算术：把算术/比较换成等价恒等式 ---- */
#define MBA_ADD(a, b) ((uint32_t)((a) ^ (b)) + 2u * ((uint32_t)(a) & (uint32_t)(b)))
#define MBA_XOR(a, b) ((uint32_t)((a) | (b)) - ((uint32_t)(a) & (uint32_t)(b)))
#define MBA_SUB(a, b) ((uint32_t)((a) ^ (b)) - 2u * ((uint32_t)(~(uint32_t)(a)) & (uint32_t)(b)))
#define MBA_EQ(a, b)  (MBA_XOR((uint32_t)(a), (uint32_t)(b)) == 0u)
#define MBA_NEQ(a, b) (MBA_XOR((uint32_t)(a), (uint32_t)(b)) != 0u)

/* ---- 垃圾指令：带 volatile 副作用，插在关键路径间 ---- */
#define JUNK() do { _obf_seed ^= (_opaque_u32(_obf_seed) >> 3); } while (0)
