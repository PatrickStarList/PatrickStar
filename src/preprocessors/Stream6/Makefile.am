## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libstream6.a

libstream6_a_SOURCES = \
PatrickStar_stream_tcp.c \
PatrickStar_stream_tcp.h \
PatrickStar_stream_udp.c \
PatrickStar_stream_udp.h \
PatrickStar_stream_icmp.c \
PatrickStar_stream_icmp.h \
PatrickStar_stream_ip.c \
PatrickStar_stream_ip.h \
stream_paf.c \
stream_paf.h \
stream_common.c \
stream_common.h 

libstream6_a_LIBADD = \
PatrickStar_stream_tcp.o \
PatrickStar_stream_udp.o \
PatrickStar_stream_icmp.o \
PatrickStar_stream_ip.o \
stream_paf.o \
stream_common.o

INCLUDES = @INCLUDES@
