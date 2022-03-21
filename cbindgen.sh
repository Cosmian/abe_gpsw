#!/bin/sh

cbindgen . -c cbindgen.toml | grep -v \#include | uniq >$1/$2.h
