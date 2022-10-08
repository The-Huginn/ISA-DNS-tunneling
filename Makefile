# author xbudin05
# Makefile for ISA DNS tunneling project
HEADERS := helpers/dnsHeader helpers/dnsUtils 
MODULES := helpers/dnsHeader helpers/dnsUtils 

HEADERS_SENDER := sender/dns_sender_events sender/utils
MODULES_SENDER := sender/dns_sender_events sender/utils

HEADERS_RECEIVER := receiver/dns_receiver_events  receiver/utils
MODULES_RECEIVER := receiver/dns_receiver_events receiver/utils

SOURCES := $(patsubst %,%.c,$(MODULES))
OBJS := $(patsubst %,%.o,$(MODULES))

SOURCES_SENDER := $(patsubst %,%.c,$(MODULES_SENDER))
OBJS_SENDER := $(patsubst %,%.o,$(MODULES_SENDER))

SOURCES_RECEIVER := $(patsubst %,%.c,$(MODULES_RECEIVER))
OBJS_RECEIVER := $(patsubst %,%.o,$(MODULES_RECEIVER))

all: sender receiver

%.o : %.c
	$(CC) $(CCFLAGS) -c $< -o $@

# Copies binary to sender/, Idk where it should be
sender: sender/dns_sender.c $(OBJS) $(OBJS_SENDER)
	$(CC) $(CCFLAGS) $(OBJS) $(OBJS_SENDER) $< -o dns_sender
	cp dns_sender sender/dns_sender

# Copies binary to receiver/, Idk where it should be
receiver: receiver/dns_receiver.c $(OBJS) $(OBJS_RECEIVER)
	$(CC) $(CCFLAGS) $(OBJS) $(OBJS_RECEIVER) $< -o dns_receiver
	cp dns_receiver receiver/dns_receiver

clean:
	rm -f $(OBJS) $(OBJS_RECEIVER) $(OBJS_SENDER) receiver/dns_receiver.o dns_receiver receiver/dns_receiver sender/dns_sender.o dns_sender sender/dns_sender