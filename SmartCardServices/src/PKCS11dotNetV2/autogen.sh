set -x

rm -f configure Makefile.in Makefile config.h.in

aclocal -I .
libtoolize --force --copy

# we do not use AC_CONFIG_HEADERS
#autoheader
automake --add-missing --foreign
autoconf
