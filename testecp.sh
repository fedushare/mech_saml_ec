#!/bin/bash

# Simple test if an IdP's ECP endpoint is running

# --------------------------------------------------------------------
#
# You need to set these parameters
#
#

# userid = a valid login id on your system
#userid="userid"
userid=$LOGNAME

# idpid = your idp entity id
# ecpurl = your idp's ECP URL

# ProtectNetwork
idpid="urn:mace:incommon:idp.protectnetwork.org"
ecpurl="https://idp.protectnetwork.org/protectnetwork-idp/profile/SAML2/SOAP/ECP"

# UIUC
#idpid="urn:mace:incommon:uiuc.edu"
#ecpurl="https://shibboleth.illinois.edu/idp/profile/SAML2/SOAP/ECP"

# NCSA
#idpid="https://idp.ncsa.illinois.edu/idp/shibboleth"
#ecpurl="https://idp.ncsa.illinois.edu/idp/profile/SAML2/SOAP/ECP"

# LIGO
#idpid="https://login.ligo.org/idp/shibboleth"
#ecpurl="https://login.ligo.org/idp/profile/SAML2/SOAP/ECP"

# Clemson
#idpid="https://idp.clemson.edu/idp/shibboleth"
#ecpurl="https://idp.clemson.edu/idp/profile/SAML2/SOAP/ECP"

# Utah
#idpid="urn:mace:incommon:utah.edu"
#ecpurl="https://incommon2.sso.utah.edu/idp/profile/SAML2/SOAP/ECP"

# UChicago
#idpid="urn:mace:incommon:uchicago.edu"
#ecpurl="https://shibboleth2.uchicago.edu/idp/profile/SAML2/SOAP/ECP"

# rpid = a valid SP entityId that is configured for ECP
rpid="https://cilogon.org/shibboleth"

# acsurl,ascurlbinding = an AssertionConsumerService URL and binding
acsurl="https://cilogon.org/Shibboleth.sso/SAML2/ECP"
acsurlbinding="urn:oasis:names:tc:SAML:2.0:bindings:PAOS"

#
# --------------------------------------------------------------------
#

# create a soap request

now="`date -u +%Y-%m-%dT%H:%M:%S`"
id="_`uuidgen | tr -d '-'`"
# note. possible id if you dont have uuidgen: "_a7849c4e7188d592b1a266a34332ffbe"

envelope='<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><S:Body><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="'${acsurl}'" ID="'${id}'" IssueInstant="'${now}'" ProtocolBinding="'${acsurlbinding}'" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'${rpid}'</saml:Issuer><samlp:NameIDPolicy AllowCreate="1"/><samlp:Scoping><samlp:IDPList><samlp:IDPEntry ProviderID="'${idpid}'"/></samlp:IDPList></samlp:Scoping></samlp:AuthnRequest></S:Body></S:Envelope>' 


# make the request

resp="`curl -k -s -H 'Content-Type: text/xml; charset=utf-8' -d \"$envelope\" -u \"${userid}\" \"${ecpurl}\" `" 

# examine what we got

echo "$resp" > testecp.out

echo "$resp" | grep -q "Fault>"  
[[ $? == 0 ]] && {
   echo "ECP request failed: soap fault!"
   echo "$resp"
   exit 1
}

echo "$resp" | grep -q "RequestUnsupported"
[[ $? == 0 ]] && {
   echo "ECP request failed: unsupported!"
   echo "$resp"
   exit 1
}

echo "$resp" | grep -q "status:Success"  
[[ $? == 0 ]] && {
   echo "ECP request successful!"
   exit 0
}

echo "ECP request failed.  response:"
echo "$resp"
exit 1

