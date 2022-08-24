#!/bin/bash

echo $FLAG > /flag 
export FLAG='not_flag'
chown root:root /flag
chmod 700 /flag

while true
do
	cp /app/pref.toml.orig /app/pref.toml
	chmod 744 /app/pref.toml
	sed -i "s/114514/$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13)/" /app/pref.toml
	cd /app
	su ctf -c 'timeout 5m ./subconverter' 2>&1
	sleep 1
done