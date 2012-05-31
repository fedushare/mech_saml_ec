#!/bin/sh

host="localhost"
port=3490
saml_ec_idp='https://boingo.ncsa.uiuc.edu/idp/profile/SAML2/SOAP/ECP'
#saml_ec_idp='https://idp.protectnetwork.org/protectnetwork-idp/profile/SAML2/SOAP/ECP'
saml_ec_user_cert=''
saml_ec_user_key=''

# If username and password passed via command line, ignore user cert/key
if [ $# -eq 2 ] 
then
    saml_ec_user_cert=''
    saml_ec_user_key=''
fi

# If user cert/key specified, do not prompt for username and password
if [ ! -s "$saml_ec_user_cert" ] || [ ! -s "$saml_ec_user_key"]
then
    if [ $# -lt 1 ] 
    then
        read -p "Enter Username: " username
    else
        username=$1
    fi 

    if [ $# -lt 2 ] 
    then
        read -s -p "Enter Password: " password
        echo
    else
        password=$2
    fi 
else
    # If using user cert/key, append 'SSL' to idp url
    saml_ec_idp="$saml_ec_idp""SSL"
fi

LD_LIBRARY_PATH=/opt/moonshot/lib64 SAML_EC_IDP="$saml_ec_idp" SAML_EC_USER_CERT="$saml_ec_user_cert" SAML_EC_USER_KEY="$saml_ec_user_key" gss-sample/gss-client -nw -nx -nm -port $port -user "$username" -pass "$password" -mech "{ 1 3 6 1 4 1 11591 4 6 }" $host test testmessage

