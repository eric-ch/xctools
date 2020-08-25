AM_CFLAGS = \
	-g -W -Wall -Werror \
	$(LIBARGO_CFLAGS) \
	$(ALSA_CFLAGS)

#
# audio_helper program.
#
noinst_HEADERS = \
	 project.h \
	 prototypes.h

bin_PROGRAMS = audio_helper

audio_helper_SOURCES = \
	main.c \
	openxtalsa.c \
	openxtdebug.c \
	openxtmixerctl.c \
	openxtargo.c \
	openxtvmaudio.c \
	unittest.c

audio_helper_LDADD = \
	$(LIBARGO_LIBS) \
	$(ALSA_LIBS)
