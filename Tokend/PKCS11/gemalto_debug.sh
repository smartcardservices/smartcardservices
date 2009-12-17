#!/bin/sh

#export DEBUGSCOPE=all
#export DEBUGDUMP=all
export DEBUGSCOPE=Gemalto.tokend,populate,exception
export DEBUGDUMP=Gemalto.tokend,populate,exception
export DEBUGDEST=/tmp/gemalto.log

exec /System/Library/Security/tokend/Gemalto.tokend/Contents/MacOS/Gemalto_debug "$@"
