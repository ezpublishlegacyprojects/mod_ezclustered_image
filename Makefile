##
##  Makefile -- Build procedure for sample ezclustered_image Apache module
##  Autogenerated via ``apxs -n ezclustered_image -g''.
##

builddir=.
top_srcdir=/usr/local/apache-2.2.9
top_builddir=/usr/local/apache-2.2.9
include /usr/local/apache-2.2.9/build/special.mk

#   the used tools
APXS=apxs
APACHECTL=apachectl

#   additional defines, includes and libraries
#DEFS=-DDEBUG_ENABLED
#INCLUDES=-I/Users/jr/downloads/softs/apache-2.2.9/modules/database
#LIBS=-L/Users/jr/downloads/softs/apache-2.2.9/modules/database/ -lmy_dbd


#   the default target
all: local-shared-build

#   install the shared object file into Apache 
install: install-modules-yes

#   cleanup
clean:
	-rm -f mod_ezclustered_image.o mod_ezclustered_image.lo mod_ezclustered_image.slo mod_ezclustered_image.la 

#   simple test
test: reload
	lynx -mime_header http://localhost/ezclustered_image

#   install and activate shared object by reloading Apache to
#   force a reload of the shared object file
reload: install restart

#   the general Apache start/restart/stop
#   procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop

