## number of questions for receiver (q_count)
* 1 means only one UDP packet and then close
* 2 means this UDP packet informs about opening TCP

## End of TCP communication (q_count)
* 2 means to keep TCP open and wait for further packets
* 1 means this was the last packet and TCP can be closed