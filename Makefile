# Target library
lib := libfs.a

all: $(lib)

## TODO: Phase 1
objs := fs.o disk.o 

CC := gcc
CFLAGS := -Wall -MMD
CFLAGS += -O2

all: $(lib)

deps := $(patsubst %.o,%.d,$(objs))
-include $(deps)

libfs.a: $(objs)
	ar rcs libfs.a $(objs)

%.o: %.c
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(lib) $(targets) $(objs) $(deps)