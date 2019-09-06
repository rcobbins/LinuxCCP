#!/bin/bash

/etc/init.d/aimprv start
mkdir /etc/opt/ssl
mv /robCA.pem /etc/opt/ssl/robCA.pem
mv /robCA.key /etc/opt/ssl/robCA.key
certtool --generate-privkey --outfile /etc/opt/ssl/server.key
certtool --generate-request --load-privkey /etc/opt/ssl/server.key --template /template --outfile /server.csr
certtool --generate-certificate --load-request /server.csr --load-ca-certificate /etc/opt/ssl/robCA.pem --load-ca-privkey /etc/opt/ssl/robCA.key --template /template --outfile /etc/opt/ssl/server.crt
rm /etc/opt/ssl/robCA.key
rm /template
rm /server.csr
/opt/CARKaim/LinuxCCP/LinuxCCP /etc/opt/ssl/server.key /etc/opt/ssl/server.crt /etc/opt/ssl/robCA.pem

while true
do
	sleep 5
done
