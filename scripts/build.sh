#!/bin/sh
BASEDIR=$(dirname "$0")
bash -c "$BASEDIR/codegen.sh"
export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib
cmake -DCMAKE_BUILD_TYPE=Debug -B .build
cmake --build .build