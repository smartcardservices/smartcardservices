#! /bin/sh

if [ -d /usr/local/include/PCSC ]
then
	echo "move /usr/local/include/PCSC away and try again"
	exit
fi

# we define PKG_CONFIG so that pkg-config is not used and PCSC_CFLAGS
# and PCSC_LIBS are used instead
PKG_CONFIG="foobar"

# find pcsc-lite header files in MacOSXCCID/
PCSC_CFLAGS="-I/System/Library/Frameworks/PCSC.framework/Versions/A/Headers"
PCSC_LIBS="-framework PCSC"

# Build a Universal Binary
CFLAGS="$CFLAGS -isysroot /Developer/SDKs/MacOSX10.6.sdk -arch i386 -arch x86_64"
LDFLAGS="-arch i386 -arch x86_64"
CONFIGURE_ARGS="--disable-dependency-tracking"

# boost
#CFLAGS="$CFLAGS -I../boost1_45"

# For Mac OS X Leopard 10.5
#CFLAGS="$CFLAGS -DMACOSX_LEOPARD"

# install in /usr
CONFIGURE_ARGS="$CONFIGURE_ARGS --prefix=/usr"

# use boost locally installed
CONFIGURE_ARGS="$CONFIGURE_ARGS --enable-system-boost"

set -x
./configure \
	PKG_CONFIG="$PKG_CONFIG" \
	CFLAGS="$CFLAGS" \
	CXXFLAGS="$CFLAGS" \
	PCSC_CFLAGS="$PCSC_CFLAGS" \
	PCSC_LIBS="$PCSC_LIBS" \
	$CONFIGURE_ARGS \
	"$@"
