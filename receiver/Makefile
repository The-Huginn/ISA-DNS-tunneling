# author xbudin05
# Makefile for ISA DNS tunneling project
HEADERS := ../helpers/dnsHeader ../helpers/dnsUtils 
MODULES := ../helpers/dnsHeader ../helpers/dnsUtils 

HEADERS_RECEIVER := dns_receiver_events  utils
MODULES_RECEIVER := dns_receiver_events utils

SOURCES := $(MODULES:%=%.c)
OBJS := $(MODULES:%=%.o)

SOURCES_RECEIVER := $(MODULES_RECEIVER:%=%.c))
OBJS_RECEIVER := $(MODULES_RECEIVER:%=%.o)

CC := gcc

all: dns_receiver.c $(OBJS) $(OBJS_RECEIVER)
	$(CC) dns_receiver.c $(OBJS) $(OBJS_RECEIVER) -o dns_receiver

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
