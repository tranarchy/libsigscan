# libsigscan

## About

libsigscan is a simple signature scanning library for Linux written in C

It supports `IDA` and `x64dbg` signature formats and it can filter by module names

## Usage

Simply move `libsigscan.c` and `libsigscan.h` to your project folder and include `libsigscan.h`

## Example

```c
pid_t pid = 14314;

char *pattern = "31 C0 48 ?? ?? 0F 84"
char *module_target = "example.so"

unsigned long long match = sig_scan(pattern, module_target, pid);
```
