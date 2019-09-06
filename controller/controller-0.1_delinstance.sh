#!/bin/bash

if [ -f "num_instances" ]; then
        num_ccp=$(cat num_instances)
else
        exit
fi

if [ $num_ccp = "0" ]; then
	exit
fi

ccp_name="cybr_ccp_"
iter=`expr 4 - $(expr length $(expr $num_ccp + 1))`
for ((i=0; i<iter; i++));
do
        ccp_name=$ccp_name"0"
done
ccp_name=$ccp_name$(expr $num_ccp)
echo $(expr $num_ccp - 1) > num_instances
docker rm -f $ccp_name

vol_dir="/home/rob/volumes/$ccp_name"
rm -rf $vol_dir

pvwapass=$(/opt/CARKaim/sdk/clipasswordsdk GetPassword -p "AppDescs.AppID=ProvAuth" -p "Query=Safe=ProvAuth;Object=ProvAuth" -o Password)
pvwauser=$(/opt/CARKaim/sdk/clipasswordsdk GetPassword -p "AppDescs.AppID=ProvAuth" -p "Query=Safe=ProvAuth;Object=ProvAuth" -o PassProps.UserName)
pvwaurl="https://components.cyberarkdemo.com/PasswordVault"
logonurl="$pvwaurl/API/auth/Cyberark/Logon"
deluserurl="$pvwaurl/WebServices/PIMServices.svc/Users"

token=$(curl -s -X POST -H "Content-Type: application/json" -k -d "{'username':'$pvwauser','password':'$pvwapass'}" $logonurl | tr -d \")

curl -s -k -X DELETE -H "Content-Type: application/json" -H "Authorization: $token" $deluserurl"/Prov_"$ccp_name
