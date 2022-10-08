# author xbudin05
# Makefile for ISA DNS tunneling project
HEADERS := ../helpers/dnsHeader ../helpers/dnsUtils 
MODULES := ../helpers/dnsHeader ../helpers/dnsUtils 

HEADERS_SENDER := dns_sender_events utils
MODULES_SENDER := dns_sender_events utils

SOURCES := $(MODULES:%=%.c)
OBJS := $(MODULES:%=%.o)

SOURCES_SENDER := $(MODULES_SENDER:%=%.c)
OBJS_SENDER := $(MODULES_SENDER:%=%.o)

CC := gcc

all: dns_sender.c $(OBJS) $(OBJS_SENDER)
	$(CC) dns_sender.c $(CFLAGS) $(OBJS) $(OBJS_SENDER) -o dns_sender

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

