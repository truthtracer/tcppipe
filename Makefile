################OPTION###################
CCOMPILE = g++
COMPILEOPTION = -g -fPIC
INCLUDEDIR = -I.
LINK = g++
LINKOPTION = -g -o tcppipe -lpthread -lm
LIBDIRS = -L/usr/local/lib
SOURCES = tcppipe.c logging.c
OBJS = $(SOURCES:.c=.o)
OUTPUT = tcppipe
PROC_OPTION = DEFINE=_PROC_ MODE=ORACLE LINES=true
ESQL_OPTION = -g
################OPTION END################
ESQL = esql
PROC = proc
$(OUTPUT):$(OBJS)
	$(LINK) $(LINKOPTION) $(LIBDIRS) $(INCLUDEDIR) $(OBJS) $(APPENDLIB)

clean: 
	rm -f $(OBJS)
	rm -f $(OUTPUT)
all: clean $(OUTPUT)
.PRECIOUS:%.cpp %.c %.C
.SUFFIXES:
.SUFFIXES:  .c .o  .pc .ec .cc


.c.o:
	$(CCOMPILE) -c -o $*.o $(COMPILEOPTION) $(INCLUDEDIR) $*.c
	
.cc.o:
	$(CCOMPILE) -c -o $*.o $(COMPILEOPTION) $(INCLUDEDIR)  $*.cpp

.ec.c:
	$(ESQL) -e $(ESQL_OPTION) $(INCLUDEDIR) $*.ec

.pc.c:
	$(PROC)  $(PROC_OPTION)  $*.pc
	
