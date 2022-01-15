#!/bin/bash

radtest -t chap username password 127.0.0.1 0 secret
#time(echo "User-Name=username1,CHAP-Password=password" | /usr/bin/radclient -q -r 1 -c 500000 localhost:1812 auth secret)
#radclient -f acct -c 1 -r 1 -t 1 -x localhost:1812 acct secret
