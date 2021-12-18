## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

INCLUDES = -I../include

noinst_libdir = ${exec_prefix}/lib/PatrickStar_dynamicrules

noinst_lib_LTLIBRARIES = lib_sfdynamic_example_rule.la

lib_sfdynamic_example_rule_la_LDFLAGS = -export-dynamic @XCCFLAGS@

BUILT_SOURCES = \
sfPatrickStar_dynamic_detection_lib.c \
sfPatrickStar_dynamic_detection_lib.h

nodist_lib_sfdynamic_example_rule_la_SOURCES = \
sfPatrickStar_dynamic_detection_lib.c \
sfPatrickStar_dynamic_detection_lib.h \
rules.c \
sid109.c \
sid637.c \
detection_lib_meta.h

EXTRA_DIST = \
rules.c \
sid109.c \
sid637.c \
detection_lib_meta.h

sfPatrickStar_dynamic_detection_lib.c: ../include/sfPatrickStar_dynamic_detection_lib.c
	cp $? $@

sfPatrickStar_dynamic_detection_lib.h: ../include/sfPatrickStar_dynamic_detection_lib.h
	cp $? $@

clean-local:
	rm -f $(BUILT_SOURCES)

