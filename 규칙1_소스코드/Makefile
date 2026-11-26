CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
LDLIBS  = -lm -pthread

VERSIONS = ini_probe_v1.1 ini_probe_v1.2 ini_probe_v1.3 ini_probe_v1.4

all: $(VERSIONS)

ini_probe_v%: ini_probe_v%.c
	$(CC) $(CFLAGS) -pthread -o $@ $< $(LDLIBS)

clean:
	rm -f $(VERSIONS)

.PHONY: all clean
