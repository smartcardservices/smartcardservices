#!/bin/sh

test `id -u` -eq 0 || { echo 'You *MUST* be root!' >&2; exit 1; }

echo '*** Install tokend ...'
rm -rf /System/Library/Security/tokend/Gemalto.tokend
ditto Tokend.root /
if test "$1" = "-d"; then
        echo '*** Blessing debug token ...'
        cp -f ./Gemalto_debug.sh \
                /System/Library/Security/tokend/Gemalto.tokend/Contents/MacOS/Gemalto
        chmod 0755 /System/Library/Security/tokend/Gemalto.tokend/Contents/MacOS/Gemalto
        chmod 0555 /System/Library/Security/tokend/Gemalto.tokend/Contents/MacOS/Gemalto_debug
else
        echo '*** Blessing release token ...'
        rm /System/Library/Security/tokend/Gemalto.tokend/Contents/MacOS/Gemalto_debug
        chmod 0555 /System/Library/Security/tokend/Gemalto.tokend/Contents/MacOS/Gemalto
fi
