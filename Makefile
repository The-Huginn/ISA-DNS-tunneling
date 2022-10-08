# author xbudin05
# Makefile for ISA DNS tunneling project
HEADERS := helpers/dnsHeader helpers/dnsUtils 
MODULES := helpers/dnsHeader helpers/dnsUtils 

HEADERS_SENDER := sender/dns_sender_events sender/utils
MODULES_SENDER := sender/dns_sender_events sender/utils

HEADERS_RECEIVER := receiver/dns_receiver_events  receiver/utils
MODULES_RECEIVER := receiver/dns_receiver_events receiver/utils

SOURCES := $(MODULES:%=%.c)
OBJS := $(MODULES:%=%.o)

SOURCES_SENDER := $(MODULES_SENDER:%=%.c)
OBJS_SENDER := $(MODULES_SENDER:%=%.o)

SOURCES_RECEIVER := $(MODULES_RECEIVER:%=%.c))
OBJS_RECEIVER := $(MODULES_RECEIVER:%=%.o)

SENDER_DIR := sender/
RECEIVER_DIR := receiver/

.PHONY: sender receiver

all: sender receiver

sender:
	$(MAKE) -C $(SENDER_DIR)

receiver:
	$(MAKE) -C $(RECEIVER_DIR)

clean:
	rm -f $(OBJS) $(OBJS_RECEIVER) $(OBJS_SENDER) receiver/dns_receiver.o dns_receiver receiver/dns_receiver sender/dns_sender.o dns_sender sender/dns_sender
