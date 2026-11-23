#!/bin/bash
# KakaVoicePro v34.1 交叉编译脚本（Linux + clang + iOS SDK）
# 依赖：clang (支持 -target arm64-apple-ios)、iOS SDK (iPhoneOS15.6.sdk)、ld64.lld
set -e

SDK="${SDK:-/workspace/work/sdks/iPhoneOS15.6.sdk}"
OUT="${OUT:-KakaVoicePro_v34.1.dylib}"

clang -target arm64-apple-ios14.0 \
  -isysroot "$SDK" \
  -dynamiclib -fobjc-arc -O2 \
  -I. \
  -o "$OUT" \
  KakaVoicePro.m tweetnacl.c fishhook.c \
  -framework UIKit \
  -framework Foundation \
  -framework AudioToolbox \
  -framework Security \
  -framework CoreGraphics \
  -framework QuartzCore \
  -Wl,-arch,arm64 \
  -Wl,-platform_version,ios,14.0,15.6 \
  -fuse-ld=/root/.rustup/toolchains/1.94.1-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld/ld64.lld

ls -l "$OUT"
shasum -a 256 "$OUT"
