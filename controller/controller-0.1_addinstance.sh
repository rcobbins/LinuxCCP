#!/bin/bash

if [ -f "num_instances" ]; then
	num_ccp=$(cat num_instances)
else
	num_ccp="0"
fi
ccp_name="cybr_ccp_"
iter=`expr 4 - $(expr length $(expr $num_ccp + 1))`
for ((i=0; i<iter; i++));
do
	ccp_name=$ccp_name"0" 
done
ccp_name=$ccp_name$(expr $num_ccp + 1)
echo $(expr $num_ccp + 1) > num_instances
vol_dir="/home/rob/volumes/$ccp_name"
mkdir $vol_dir
mkdir "$vol_dir/etcvault"
mkdir "$vol_dir/etcconf"
cp vault.ini "$vol_dir/etcvault/vault.ini"
cp basic_appprovider.conf "$vol_dir/etcconf/basic_appprovider.conf"

pvwapass=$(/opt/CARKaim/sdk/clipasswordsdk GetPassword -p "AppDescs.AppID=ProvAuth" -p "Query=Safe=ProvAuth;Object=ProvAuth" -o Password)
pvwauser=$(/opt/CARKaim/sdk/clipasswordsdk GetPassword -p "AppDescs.AppID=ProvAuth" -p "Query=Safe=ProvAuth;Object=ProvAuth" -o PassProps.UserName)
pvwaurl="https://components.cyberarkdemo.com/PasswordVault"
logonurl="$pvwaurl/API/auth/Cyberark/Logon"
adduserurl="$pvwaurl/api/Users"
safeurl="$pvwaurl/WebServices/PIMServices.svc/Safes"
password=$(tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1) > /dev/null
./createcredfile $vol_dir/etcvault/appprovideruser.cred Password -Username Prov_$ccp_name -Password $password > /dev/null

token=$(curl -s -X POST -H "Content-Type: application/json" -k -d "{'username':'$pvwauser','password':'$pvwapass'}" $logonurl | tr -d \")
body=$(cat <<EOF
{"username":"Prov_$ccp_name","initialPassword":"$password","changePassOnNextLogon":false,"passwordNeverExpires":true,"userType":"AppProvider","location":"\\\\Applications","VaultAuthorization":["AuditUsers","AddUpdateUsers"]}
EOF
)
curl -s -k -X POST -H "Content-Type: application/json" -H "Authorization: $token" -d $body $adduserurl > /dev/null

body=$(cat <<EOF
{"member":{"MemberName":"Prov_$ccp_name","Permissions":[{"Key":"UseAccounts","Value":true},{"Key":"RetrieveAccounts","Value":true},{"Key":"ListAccounts","Value":true},{"Key":"AddAccounts","Value":true},{"Key":"UpdateAccountContent","Value":true},{"Key":"UpdateAccountProperties","Value":true},{"Key":"RenameAccounts","Value":true},{"Key":"CreateFolders","Value":true}]}}
EOF
)
curl -s -k -X POST -H "Content-Type: application/json" -H "Authorization: $token" -d $body "$safeurl/AppProviderConf/Members" > /dev/null

body=$(cat <<EOF
{"member":{"MemberName":"Prov_$ccp_name","Permissions":[{"Key":"UseAccounts","Value":true},{"Key":"RetrieveAccounts","Value":true},{"Key":"ListAccounts","Value":true}]}}
EOF
)
while read -r safename
do
	curl -s -k -X POST -H "Content-Type: application/json" -H "Authorization: $token" -d $body "$safeurl/$safename/Members" > /dev/null
done < safeslist

cp template template.tmp
sed -i "s/cn=\"\"/cn = \"$ccp_name\"/" template.tmp
serial=$(cat serial)
echo $(expr $serial + 1) > serial
sed -i "s/serial = \"\"/serial = $serial/" template.tmp
docker create -it -v $vol_dir/etcvault:/etc/opt/CARKaim/vault -v $vol_dir/etcconf:/etc/opt/CARKaim/conf --name $ccp_name --expose 9500 cybr-rob/linuxccp:latest > /dev/null
docker cp ./template.tmp $ccp_name:/template
docker cp ./robCA.key $ccp_name:/
docker cp ./robCA.pem $ccp_name:/
docker start $ccp_name > /dev/null

