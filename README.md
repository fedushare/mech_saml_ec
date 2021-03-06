This is an open source implementation of https://tools.ietf.org/html/draft-ietf-kitten-sasl-saml-ec

View and report issues at: https://github.com/fedushare/mech_saml_ec/issues

Discuss at: https://groups.google.com/d/forum/saml-ec-gssapi-dev

## Installing required RPMs

Instructions for obtaining Shibboleth RPMs are available at:

https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPLinuxRPMInstall

For RHEL/CentOS based systems the basic steps are:

1. Create a new file `/etc/yum.repos.d/shibboleth.repo`:
    ```
    [Shibboleth]
    name=Shibboleth
    baseurl=http://download.opensuse.org/repositories/security://shibboleth/<OS>
    enabled=1
    gpgcheck=0
    ```

    And replace the `<OS>` at the end of `baseurl` with the target operating system.

2. Install required packages with "yum":
    ```Shell
    # sudo yum -y install \
        shibboleth \
        shibboleth-devel \
        libxerces-c-3_1 \
        libxerces-c-devel \
        libsaml7 \
        libsaml-devel \
        opensaml-schemas \
        liblog4shib1 \
        liblog4shib-devel \
        libxml-security-c16 \
        libxml-security-c-devel \
        libxmltooling5 \
        libxmltooling-devel \
        xmltooling-schemas \
        libevent \
        libxml2-devel \
        libtool \
        gcc \
        gcc-c++ \
        byacc \
        libcurl \
        libcurl-devel
    ```

3. If you are running RHEL6 (may also apply to CentOS6), you may encounter a
warning about libcurl which causes the library to segfault. This is due to
Red Hat using Netscape Security Services stack (NSS) instead of OpenSSL for
the curl libraries. See the following for more information:
https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPLinuxRH6

## SP Configuration

The library depends on correct configuration of the Shibboleth Service
Provider (SP) software. In particular, you need to choose an entityID for
your SP, create metadata for the SP (which is needed by any Identity Provider
(IdP) you use), and configure a few files in `/etc/shibboleth/`.  In
particular, you need to modify the following files.

1. `/etc/shibboleth/shibboleth2.xml`

    This is the main Shibboleth SP configuration file. You should be able to use
    the provided shibboleth2.xml.dist file as a starting point. You must set the
    following sections:

    1. `ApplicationDefaults`
        ```
        <ApplicationDefaults entityID="https://your.org/shibboleth"
                             REMOTE_USER="persistent-id targeted-id eppn"
                             signing="true">
        ```
        The entityID is set to your chosen entityID and must match the entityID
        in the metadata for the SP. "signing" must be set to true so that SAML
        messages passed between the server and client are signed.

    2. `MetadataProvider`
        ```
        <MetadataProvider ...>
        ```
        You must have at least one MetadataProvider section so the library
        can verify the IdP used to authenticate the user.

2. `/etc/shibboleth/attribute-map.xml`

    In order to get a local user name for the authenticated user, you must map
    one attribute released by the IdP to "local-login-user". This actually
    requires two steps:

    1. The IdP must be configured to release an attribute to your SP's
    entityID.  It's not critical WHICH attribute is released, as long as
    the IdP and SP agree. For this discussion, let's say the IdP has
    released "givenName" (urn:oid:2.5.4.42).

    2. On the SP side, map this attribute to "local-login-user" by adding the
    following to attribute-map.xml:
        ```
        <Attribute name="urn:oid:2.5.4.42" id="local-login-user"/>
        ```

3. Metadata

    The following AssertionConsumerService should be added to the SP metadata consumed
    by the IdP.

    ```
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:PAOS" Location="host@<fqdn>" index="<index>"/>
    ```

    Replace `<fqdn>` with the fully qualified domain name of your SP and `<index>` with this AssertionConsumerService's
    index in the SP's list of all AssertionConsumerServices.

## Testing your IdP configuration

Before trying the SAML EC GSS mechanism, first confirm that your SAML
IdP supports the SAML ECP Profile. A testecp.sh shell script (from the
Shibboleth project) is provided for this purpose. Edit the testecp.sh
file to set the needed parameters, then run it:

```
# ./testecp.sh
Enter host password for user 'example':
ECP request successful!
```

## Building The Code

```
# ./autogen.sh
# ./configure
# make
```

## Running in Debug Mode

Copious debugging info can be seen by setting the environment variable
MECH_SAML_EC_DEBUG.

```
$ export MECH_SAML_EC_DEBUG=anyvalue
```

## ECP ChannelBindings configuration

Place the following in `~/.gss_saml_ec_cb_type`:
```
tls-server-end-point
```

Note this requires tls-server-end-point ChannelBindings support in the IdP (included in Shibboleth IdP v2.4.0 and later).

## Testing Library with MIT GSS example programs

1. Start Server as follows. In one window, run:

    ```
    # ./testserver.sh
    ```

    OR

    ```
    # cd gss-sample
    # ./gss-server -port 3490 test
    ```

2. Invoke client as follows. In a second window, run:

    ```
    # ./testclient.sh <username> <password>
    ```

    OR

    ```
    # cd gss-sample
    # export SAML_EC_IDP='https://idp.protectnetwork.org/protectnetwork-idp/profile/SAML2/SOAP/ECP'    # Use your IdP's ECP endpoint
    # ./gss-client -nw -nx -nm -port 3490 -user <username> -pass <password> -mech "{ 1 3 6 1 4 1 11591 4 6 }" localhost host@fqdn testmessage # must match host@fqdn in AssertionConsumerService Location
    ```

## Using ProtectNetwork's IdP

If you don't have an ECP-enabled IdP already, one option is to use
ProtectNetwork.

First, federate your SP with the ProtectNetwork IdP:

http://www.protectnetwork.org/support/integrate-protectnetwork-metadata/shibboleth-sp2x

As documented on the above page, you must configure your SP with
ProtectNetwork's metadata and register your SP with ProtectNetwork.

To register your SP with ProtectNetwork, you must first apply for a
ProtectNetwork Administrator account:

https://app.protectnetwork.org/adminRegistration.html

Then use the 'Administrator Login' link:

https://app.protectnetwork.org/admin/login

Then click the Add Site button to add a new SP and wait for approval.

To actually log in via SAML ECP, you need to register for a
ProtectNetwork UserID:

https://app.protectnetwork.org/registration.html

Finally, you can use the ProtectNetwork IdP's ECP endpoint to log in
with your ProtectNetwork UserID and password:

```
export SAML_EC_IDP='https://idp.protectnetwork.org/protectnetwork-idp/profile/SAML2/SOAP/ECP'
```

## Using with OpenSSH for User Authentication

[Download and install](https://wiki.moonshot.ja.net/display/Moonshot/Install+Moonshot+Libraries+on+a+Client) the
[Moonshot Identity Selector](https://wiki.moonshot.ja.net/display/Moonshot/The+Moonshot+Identity+Selector).

Download and install latest krb5 (>= 1.10) from http://web.mit.edu/kerberos/

```
cd krb5-1.10.3/src
CFLAGS=-g ./configure --prefix=$HOME/krb5-install --enable-shared
make
make install
```

Place the following in `$HOME/krb5-install/etc/gss/mech`:
```
saml-ec 1.3.6.1.4.1.11591.4.6 mech_saml_ec.so
```

Place mech_saml_ec.so in `$HOME/krb5-install/lib/gss/`

Place the following in `$HOME/krb5-install/etc/krb5.conf`:
```
[libdefaults]
    default_realm = YOUR_DOMAIN_ALL_CAPS
```

Download and install Project Moonshot OpenSSH

```
git clone http://www.project-moonshot.org/git/openssh.git
cd openssh/
./configure --prefix=$HOME/openssh-moonshot --with-kerberos5=$HOME/krb5-install --with-libmoonshot
make install
```

NOTE: If krb5 version is too old, compiler errors would look like:

```
undefined reference to `gss_pname_to_uid'
undefined reference to `gss_userok'
```

Enable GSSAPI, disable Privilege Separation in `openssh-moonshot/etc/sshd_config`:

```
GSSAPIAuthentication yes
UsePrivilegeSeparation no
```

Enable GSSAPI in `openssh-moonshot/etc/ssh_config`:
```
GSSAPIAuthentication yes
```

Run Server as root:
```
# cd openssh-moonshot/sbin
# ./sshd -p 2222 -ddd -r
```

If using the Moonshot Identity Selector, [add an identity with your IdP username and password to
it](https://wiki.moonshot.ja.net/display/Moonshot/User+Guide#UserGuide-AddinganIdentity). In the issuer field,
put your IdP's ECP single sign on service's location (ex. https://idp.example.com/idp/profile/SAML2/SOAP/ECP).

Otherwise, put your IdP username/password in `~/.gss_eap_id`, like:
```
username
password
```
and set an environment variable with your IdP's ECP single sign on service's location:
```
export SAML_EC_IDP="https://idp.example.com/idp/profile/SAML2/SOAP/ECP"
```

Run Client: (if using the Moonshot Identity Selector, this must be run in a graphical environment)
```
$ # First set IdP as shown next
$ export SAML_EC_IDP=https://idp.protectnetwork.org/protectnetwork-idp/profile/SAML2/SOAP/ECP
$ cd openssh-moonshot/bin
$ ./ssh -vvv -p 2222 fqdn # must match host@fqdn in AssertionConsumerService Location
```

## IdP v3

By default, version 3 of the Shibboleth IdP will reject relying party endpoints that do not use either `http` or `https`
URL schemes. To allow the IdP to send assertions to `mech_saml_ec`'s `host@fqdn` AssertionConsumerService (which the
IdP interprets as using a `null` URL scheme), add the following to `$IDP_HOME/conf/global.xml`:

```xml
<bean class="org.springframework.beans.factory.config.MethodInvokingBean" depends-on="shibboleth.OpenSAMLConfig">
    <property name="targetClass" value="org.opensaml.saml.config.SAMLConfigurationSupport"/>
    <property name="targetMethod" value="setAllowedBindingURLSchemes"/>
    <property name="arguments">
        <list>
            <util:list>
                <value>http</value>
                <value>https</value>
                <null />
            </util:list>
        </list>
    </property>
</bean>
```

## Acknowledgements

Development of this software was supported in part by a gift from the
[Internet Society](https://www.internetsociety.org).

This material is based upon work supported by the [National Science Foundation](https://www.nsf.gov/) under grant number [1440609](https://www.nsf.gov/awardsearch/showAward?AWD_ID=1440609).
Any opinions, findings, and conclusions or recommendations expressed in this material are those of the authors and do not necessarily reflect the views of the United States Government or any agency thereof.
