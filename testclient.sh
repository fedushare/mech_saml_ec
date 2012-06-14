#!/bin/sh

host='localhost'
port=3490
idp='https://idp.protectnetwork.org/protectnetwork-idp/profile/SAML2/SOAP/ECP'
#idp='https://boingo.ncsa.uiuc.edu/idp/profile/SAML2/SOAP/ECP'
user_cert="$SAML_EC_USER_CERT"
user_key="$SAML_EC_USER_KEY"

# If username and password passed via command line, ignore user cert/key
if [ $# -eq 2 ] ; then
    user_cert=''
    user_key=''
fi

# If user cert/key is not specified, prompt for missing username/password
if [ ! -s "$user_cert" ] || [ ! -s "$user_key"] ; then
    if [ $# -lt 1 ] ; then
        read -p "Enter Username: " username
    else
        username=$1
    fi 

    if [ $# -lt 2 ] ; then
        read -s -p "Enter Password: " password
        echo
    else
        password=$2
    fi 
else
    # If using user cert/key with boingo, append 'SSL' to idp url
    if [ $idp="https://boingo.ncsa.uiuc.edu/idp/profile/SAML2/SOAP/ECP" ] ; then
        idp="$dp""SSL"
    fi
fi

SAML_EC_IDP="$idp" SAML_EC_USER_CERT="$user_cert" SAML_EC_USER_KEY="$user_key" gss-sample/gss-client -nw -nx -nm -port $port -user "$username" -pass "$password" -mech "{ 1 3 6 1 4 1 11591 4 6 }" $host test testmessage

