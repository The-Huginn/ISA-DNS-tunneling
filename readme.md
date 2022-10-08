# Welcome to the ISA DNS tunneling project

## Client side
flags:
* `{-b BASE_HOST}` for specifying host name
* `[-u DNS_SERVER_IP]` for specifying dns server side
* `{DST_FILE}` under which file we save communication on server
* `[SRC_FILE]` input file, if not specified, `stdin` is used
* `[-d]` to not use encryption

Client side tries to communicate with the DNS server, which is running the `dns_receiver` runnable. This communication is saved on server

## Server side
flags:
* `{BASE_HOST}` for specifying the base host of the DNS server
* `{DST_FILEPATH}` for specifying path, under which we create file
* `[-d]` to not use encryption

Server waits for communication with `dns_sender` and saves the communication into specified path like: `DST_FILEPATH/SRC_FILE`

## Implementation details

### number of questions for receiver (q_count)
* 1 means only one UDP packet and then close
* 2 means this UDP packet informs about opening TCP

### End of TCP communication (q_count)
* 2 means to keep TCP open and wait for further packets
* 1 means this was the last packet and TCP can be closed

### Encryption
Basic ceasar encryption is used to prevent easily reading the content of communication.

### Notes
* server does not allow communication with multiple senders
* server does not allow normal dns communication
* sender creates 2 processes where one logs return actions from the server. Because of this the shutdown of sender takes additional time to log incoming messages.
* sender after every TCP packet sent (usually TCP_MTU bytes) sleeps for one second.