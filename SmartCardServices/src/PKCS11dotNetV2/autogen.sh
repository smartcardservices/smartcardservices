set -x

# create symlinks for external directories
[ -e config ] || ln -s ../../_BIN/config
[ -e docs ] || ln -s ../docs

rm -f configure Makefile.in Makefile config.h.in

aclocal -I .
libtoolize --force --copy

# we do not use AC_CONFIG_HEADERS
#autoheader
automake --add-missing --foreign
autoconf
