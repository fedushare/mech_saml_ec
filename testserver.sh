#!/bin/sh

LD_LIBRARY_PATH=/opt/moonshot/lib64 SAML_EC_IDP='https://boingo.ncsa.uiuc.edu/idp/profile/SAML2/SOAP/ECP' gss-sample/gss-server -port 3490 test
