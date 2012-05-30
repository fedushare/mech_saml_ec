#!/bin/sh

host="localhost"
port=3490

if [ $# -ne 1 ] 
then
    read -p "Enter Username: " username
else
    username=$1
fi 

if [ $# -ne 2 ] 
then
    read -s -p "Enter Password: " password
    echo
else
    password=$2
fi 

LD_LIBRARY_PATH=/opt/moonshot/lib64 SAML_EC_IDP='https://boingo.ncsa.uiuc.edu/idp/profile/SAML2/SOAP/ECP' gss-sample/gss-client -nw -nx -nm -port $port -user "$username" -pass "$password" -mech "{ 1 3 6 1 4 1 11591 4 6 }" $host test testmessage
