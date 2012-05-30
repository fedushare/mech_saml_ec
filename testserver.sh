#!/bin/sh

port=3490

LD_LIBRARY_PATH=/opt/moonshot/lib64 gss-sample/gss-server -port $port test
