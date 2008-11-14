#
# Makefile to build aekavd
#
#

#
# files and dirs
#

src_files = aekavd.cc session.cc kav.cc pidfile.cc options.cc error.cc
obj_files = $(src_files:.cc=.o)
dep_files = $(src_files:.cc=.d)

libs = -lkave8 -ldl -lrt

# todo: fix kav dirs
kav_include_dir = ../KAV_SDK8_L3/include
kav_lib_dir     = ../KAV_SDK8_L3/lib
install_bin_dir = $(DESTDIR)/usr/sbin

#
# flags and programs
#
CXX     ?= c++
INSTALL  = install

CPPFLAGS      += -I $(kav_include_dir)
CXXFLAGS      += $(CPPFLAGS) -Wall -g
LDFLAGS       += -L $(kav_lib_dir)
INSTALL_FLAGS = -m 755

#
# rules
#
%.d: %.cc
	@set -e; rm -f $@; \
	$(CXX) -M $(CPPFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

%.o: %.cc
	$(CXX) $(CXXFLAGS) -o $@ -c $<


#
# targets
#

.PHONY: all clean install uninstall tests

all: aekavd

clean:
	$(RM) $(obj_files) $(dep_files) aekavd test-read-config core

aekavd: $(obj_files)
	$(CXX) $(LDFLAGS) -o $@ $(obj_files) $(libs)

install:
	$(INSTALL) $(INSTALL_FLAGS) aekavd $(install_bin_dir)/aekavd

uninstall:
	$(RM) $(install_bin_dir)/aekavd

tests: test-read-config

test-read-config: test-read-config.cc options.cc error.cc
	$(CXX) $(CXXFLAGS) -o $@ $^

ifneq ($(MAKECMDGOALS),clean)
-include $(dep_files)
endif
