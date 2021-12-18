AUTOMAKE_OPTIONS=foreign
bin_PROGRAMS = PatrickStar_control PatrickStar_dump_packets_control

docdir = ${datadir}/doc/${PACKAGE}

PatrickStar_control_SOURCES = sfcontrol.c
PatrickStar_control_CFLAGS = @CFLAGS@ $(AM_CFLAGS)

PatrickStar_dump_packets_control_SOURCES = PatrickStar_dump_packets.c
PatrickStar_dump_packets_control_CFLAGS = @CFLAGS@ $(AM_CFLAGS)

INCLUDES = @INCLUDES@ @extra_incl@

dist_doc_DATA = README.PatrickStar_control README.PatrickStar_dump_packets_control

