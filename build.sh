#!/usr/bin/env bash

set -e

TYPE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --t)
            if [ -z "$2" ]; then
                echo "Error: missing build type"
                echo "Usage: $0 --t debug|release"
                exit 1
            fi

            TYPE="$2"
            shift 2
            ;;

        *)
            echo "Error: unknown argument: $1"
            echo "Usage: $0 --t debug|release"
            exit 1
            ;;
    esac
done

if [ "$TYPE" != "debug" ] && [ "$TYPE" != "release" ]; then
    echo "Error: build type must be debug or release"
    echo "Usage: $0 --t debug|release"
    exit 1
fi

BUILD_TYPE="Debug"

if [ "$TYPE" = "release" ]; then
    BUILD_TYPE="Release"
fi

BUILD_DIR="build/$TYPE"

echo "================================"
echo " Building ZeroTrust"
echo " Type: $BUILD_TYPE"
echo " Directory: $BUILD_DIR"
echo "================================"

cmake -S . -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE"

cmake --build "$BUILD_DIR" --parallel

echo ""
echo "================================"
echo " Build successful!"
echo " Binary: $BUILD_DIR/zerotrust"
echo "================================"