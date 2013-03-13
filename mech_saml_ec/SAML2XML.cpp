#include <shibsp/AbstractSPRequest.h>
#include <shibsp/Application.h>
#include <shibsp/SPConfig.h>
#include <shibsp/ServiceProvider.h>
#include <shibsp/attribute/Attribute.h>
#include <shibsp/attribute/resolver/ResolutionContext.h>
#include <shibsp/handler/Handler.h>
#include <shibsp/handler/AssertionConsumerService.h>
#include <shibsp/metadata/MetadataProviderCriteria.h>
#include <shibsp/util/SPConstants.h>
#include <saml/exceptions.h>
#include <saml/SAMLConfig.h>
#include <saml/binding/SecurityPolicy.h>
#include <saml/binding/SecurityPolicyRule.h>
#include <saml/saml1/core/Assertions.h>
#include <saml/saml1/core/Protocols.h>
#include <saml/saml2/core/Assertions.h>
#include <saml/saml2/core/Protocols.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataCredentialCriteria.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <saml/signature/ContentReference.h>
#include <saml/util/SAMLConstants.h>
#include <xercesc/dom/DOM.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/exceptions.h>
#include <xmltooling/soap/SOAP.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/impl/AnyElement.h>
#include <xmltooling/security/Credential.h>
#include <xmltooling/security/CredentialResolver.h>
#include <xmltooling/security/SignatureTrustEngine.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/util/ParserPool.h>
#include <xmltooling/util/XMLHelper.h>
#include <xmltooling/util/XMLConstants.h>
#include <xmltooling/util/DateTime.h>
#include <xmltooling/validation/ValidatorSuite.h>
#include <iostream>
#include <sstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

using namespace opensaml::saml2;
using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace samlconstants;
using namespace shibsp;
using namespace soap11;
using namespace xercesc;
using namespace xmlconstants;
using namespace xmlsignature;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

static ResolutionContext* ctx = nullptr;

// Taken from http://stackoverflow.com/questions/504810/
static string getfqdn()
{
    string retstr;
    struct addrinfo hints, *info, *p;
    int gai_result;

    char hostname[1024];
    hostname[1023] = '\0';
    gethostname(hostname, 1023);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; /*either IPV4 or IPV6*/
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;

    if ((gai_result = getaddrinfo(hostname, "http", &hints, &info)) != 0) {
        retstr = "localhost";
    }

    for (p = info; p != NULL; p = p->ai_next) {
        retstr = p->ai_canonname;
    }

    freeaddrinfo(info);
    return retstr;
}

// Taken from AbstractHandler.cpp
void generateRandomHex(std::string& buf, unsigned int len) {
    static char DIGITS[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    int r;
    unsigned char b1,b2;
    buf.erase();
    for (unsigned int i=0; i<len; i+=4) {
        r = rand();
        b1 = (0x00FF & r);
        b2 = (0xFF00 & r)  >> 8;
        buf += (DIGITS[(0xF0 & b1) >> 4 ]);
        buf += (DIGITS[0x0F & b1]);
        buf += (DIGITS[(0xF0 & b2) >> 4 ]);
        buf += (DIGITS[0x0F & b2]);
    }
}

// Set the config options only once
SPConfig& getConf(void) {
    static SPConfig& conf = SPConfig::getConfig();
    static int featuresSet = 0;
    if (!featuresSet) {
        featuresSet = 1;
        conf.setFeatures(
            SPConfig::Metadata |
            SPConfig::Trust |
            SPConfig::AttributeResolution |
            SPConfig::Credentials |
            SPConfig::OutOfProcess |
            SPConfig::Caching |
            SPConfig::Logging |
            SPConfig::Handlers
        );
    }
    return conf;
}

// Taken from resolvertest.cpp
// This is necessary since resolveAttributes is protected and thus cannot be called 
// from a local instance of a Handler/AssertionConsumerService object.
class LocalResolver : public shibsp::AssertionConsumerService
{
public:
    LocalResolver(const DOMElement* e, const char* appId)
        : shibsp::AssertionConsumerService(e, appId, Category::getInstance(SHIBSP_LOGCAT".Utilities.LocalResolver")) {
    }
    virtual ~LocalResolver() {}
    
    ResolutionContext* resolveAttributes (
        const Application& application,
        const RoleDescriptor* issuer,
        const XMLCh* protocol,
        const saml1::NameIdentifier* v1nameid,
        const saml2::NameID* nameid,
        const XMLCh* authncontext_class,
        const XMLCh* authncontext_decl,
        const vector<const opensaml::Assertion*>* tokens
        ) const {
        return shibsp::AssertionConsumerService::resolveAttributes(
            application, issuer, protocol, v1nameid, nameid, authncontext_class, authncontext_decl, tokens
            );
    }

private:
    void implementProtocol(
        const Application& application,
        const HTTPRequest& httpRequest,
        HTTPResponse& httpResponse,
        SecurityPolicy& policy,
        const PropertySet* settings,
        const XMLObject& xmlObject
        ) const {
            throw FatalProfileException("Should never be called.");
    }
};


extern "C" char* getSAMLRequest2(char *name, int name_len, int signatureRequested,
                               char *channel_bindings)
{
    string retstr = "";

    // Initialization code taken from resolvertest.cpp::main()
    SPConfig& conf = getConf();
    if (conf.init()) {
        if (conf.instantiate()) {
            ServiceProvider* sp = conf.getServiceProvider();
            sp->lock();
            const Application* app = sp->getApplication("default");
            if (app) {

                // Taken from constructor SAML2SessionInitiator::SAML2SessionInitiator()
                // BUT, e is "const DOMElement*" and I have no idea what
                // actually calls the constructor, so no idea what 'e' is.
                // Thus the encoder may be incomplete.
                DOMElement* e = 0;
                try {
                    const MessageEncoder* encoder = SAMLConfig::getConfig().MessageEncoderManager.newPlugin(SAML20_BINDING_PAOS, pair<const DOMElement*,const XMLCh*>(e,nullptr));
                    delete encoder;
                } catch (exception & ex) {
                }
                
                // Now in SAML2SessionInitiator::doRequest()
                pair<const EntityDescriptor*,const RoleDescriptor*> entity = 
                    pair<const EntityDescriptor*,const RoleDescriptor*>(nullptr,nullptr);
                const IDPSSODescriptor* role = nullptr;
                const EndpointType* ep = nullptr;

                MetadataProvider* m = app->getMetadataProvider();
                Locker mlocker(m);

                // Taken from AbstractHandler.cpp Handler::preserveRelayState()
                string relayStateStr = "";
                string rsKey;
                generateRandomHex(rsKey,5);
                relayStateStr = "cookie:" + rsKey;
                const char* relayState = relayStateStr.c_str();

                // Get the AssertionConsumerService
                const Handler* ACS=nullptr;
                ACS = app->getAssertionConsumerServiceByProtocol(SAML20P_NS,SAML20_BINDING_PAOS);
                if (!ACS)
                    throw XMLToolingException("Unable to locate PAOS response endpoint.");

                // Build up AuthnRequest section of the SOAP message
                auto_ptr<AuthnRequest> request(AuthnRequestBuilder::buildAuthnRequest());
                
                // Taken from AbstractSPRequest::getHandlerURL()
                string m_handlerURL;
                string fqdn = getfqdn();
                string resourcestr;
                const char* resource;
                resourcestr = "https://" + fqdn + "/";
                resource = resourcestr.c_str();
                const char* handler = nullptr;
                const PropertySet* props = app->getPropertySet("Sessions");
                if (props) {
                    pair<bool,const char*> p2 = props->getString("handlerURL");
                    if (p2.first) {
                        handler = p2.second;
                    }
                }

                if (!handler) {
                    handler = "/Shibboleth.sso";
                } else if (*handler!='/' && strncmp(handler,"http:",5) && strncmp(handler,"https:",6)) {
                    throw XMLToolingException(
                          "Invalid handlerURL property <Sessions> element for Application");
                }

                const char* path = nullptr;
                const char* prot;
                if (*handler != '/') {
                    prot = handler;
                } else {
                    prot = resource;
                    path = handler;
                }

                // break apart the "protocol" string into protocol, host, and "the rest"
                const char* colon=strchr(prot,':');
                colon += 3;
                const char* slash=strchr(colon,'/');
                if (!path) {
                    path = slash;
                }

                // Compute the actual protocol and store in m_handlerURL.
                m_handlerURL.assign("https://");
                // create the "host" from either the colon/slash or from the target string
                // If prot == handler then we're in either #1 or #2, else #3.
                // If slash == colon then we're in #2.
                if (prot != handler || slash == colon) {
                    colon = strchr(resource, ':');
                    colon += 3;      // Get past the ://
                    slash = strchr(colon, '/');
                }
                string host(colon, (slash ? slash-colon : strlen(colon)));

                // Build the handler URL
                m_handlerURL += host + path;
                // END code from AbstractSPRequest::getHandlerURL()

                pair<bool,const char*> prop;
                prop = ACS->getString("Location");
                if (prop.first) {
                    m_handlerURL += prop.second;
                    // This is to enable the initiator (eg: ssh client) to check
                    // the target name passed in by the ssh client which is
                    // of the form host@<hostname>
                    if (name)
                        m_handlerURL.assign(name, name_len);
                }

                // auto_ptr_XMLCh acsLocation("https://test.cilogon.org/Shibboleth.sso/SAML2/ECP");
                auto_ptr_XMLCh acsLocation(m_handlerURL.c_str());
                request->setAssertionConsumerServiceURL(acsLocation.get());

                Issuer* issuer = IssuerBuilder::buildIssuer();
                request->setIssuer(issuer);
                issuer->setName(app->getRelyingParty(entity.first)->getXMLString("entityID").second);

                auto_ptr_XMLCh acsBinding((ACS->getString("Binding")).second);
                request->setProtocolBinding(acsBinding.get());

                NameIDPolicy* namepol = NameIDPolicyBuilder::buildNameIDPolicy();
                namepol->AllowCreate(true);
                request->setNameIDPolicy(namepol);

                opensaml::saml2p::Extensions* exten = opensaml::saml2p::ExtensionsBuilder::buildExtensions();
                request->setExtensions(exten);

                XMLObject* requestobj = request.get();
             
                // Taken from AbstractHandler.cpp
                // sendMessage(*encoder,requestobj,relayState.c_str(),dest.get()[=nullptr],
                //             role[=nullptr],app,httpResponse,false);
                const EntityDescriptor* entity2 = nullptr;
                const PropertySet* relyingParty = app->getRelyingParty(entity2);
                pair<bool,const char*> flag = relyingParty->getString("signing");
                const Credential* cred = nullptr;
                pair<bool,const char*> keyName;
                pair<bool,const XMLCh*> sigalg;
                pair<bool,const XMLCh*> digalg;
                if (((flag.first) && (!strcmp(flag.second,"true"))) ||
                                   signatureRequested) {
                    CredentialResolver* credResolver = app->getCredentialResolver();
                    if (credResolver) {
                        Locker credLocker(credResolver);
                        keyName = relyingParty->getString("keyName");
                        sigalg = relyingParty->getXMLString("signingAlg");
                        CredentialCriteria cc;
                        cc.setUsage(Credential::SIGNING_CREDENTIAL);
                        if (keyName.first) {
                            cc.getKeyNames().insert(keyName.second);
                        }
                        if (sigalg.first) {
                            cc.setXMLAlgorithm(sigalg.second);
                        }
                        cred = credResolver->resolve(&cc);
                        if (cred) {
                            // Signed request.
                            digalg = relyingParty->getXMLString("digestAlg");
                        }
                    }
                }
                // Call into opensaml's SAML2ECPEncoder.cpp
                // return encoder.encode(httpResponse,requestobj,dest.get()[=nullptr],
                //                       entity2[=nullptr],relayState.c_str(),&app)
                Envelope* env = EnvelopeBuilder::buildEnvelope();
                Header* header = HeaderBuilder::buildHeader();
                env->setHeader(header);
                Body* body = BodyBuilder::buildBody();
                env->setBody(body);
                body->getUnknownXMLObjects().push_back(requestobj);

                ElementProxy* hdrblock;
                xmltooling::QName qMU(SOAP11ENV_NS, Header::MUSTUNDERSTAND_ATTRIB_NAME,
                                      SOAP11ENV_PREFIX);
                xmltooling::QName qActor(SOAP11ENV_NS, Header::ACTOR_ATTRIB_NAME, 
                                         SOAP11ENV_PREFIX);
                
                // Create paos:Request header.
                AnyElementBuilder m_anyBuilder;
                auto_ptr_XMLCh m_actor("http://schemas.xmlsoap.org/soap/actor/next");
                static const XMLCh service[] = UNICODE_LITERAL_7(s,e,r,v,i,c,e);
                static const XMLCh responseConsumerURL[] = UNICODE_LITERAL_19(r,e,s,p,o,n,s,e,C,o,n,s,u,m,e,r,U,R,L);
                hdrblock = dynamic_cast<ElementProxy*>(m_anyBuilder.buildObject(PAOS_NS, saml1p::Request::LOCAL_NAME, PAOS_PREFIX));
                hdrblock->setAttribute(qMU, XML_ONE);
                hdrblock->setAttribute(qActor, m_actor.get());
                hdrblock->setAttribute(xmltooling::QName(nullptr, service), SAML20ECP_NS);
                hdrblock->setAttribute(xmltooling::QName(nullptr, responseConsumerURL), request->getAssertionConsumerServiceURL());
                header->getUnknownXMLObjects().push_back(hdrblock);

                // Create samlec:SessionKey header block.
                static const XMLCh SESSION_KEY[] = UNICODE_LITERAL_10(S,e,s,s,i,o,n,K,e,y);
                static const XMLCh SAMLEC_PREFIX[] = UNICODE_LITERAL_6(s,a,m,l,e,c);
                static const XMLCh SAMLEC_NS[] = { chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_i, chLatin_e, chLatin_t, chLatin_f, chColon, chLatin_p, chLatin_a, chLatin_r, chLatin_a, chLatin_m, chLatin_s, chColon, chLatin_x, chLatin_m, chLatin_l, chColon, chLatin_n, chLatin_s, chColon, chLatin_s, chLatin_a, chLatin_m, chLatin_l, chLatin_e, chLatin_c, chNull };
                hdrblock = dynamic_cast<ElementProxy*>(m_anyBuilder.buildObject(SAMLEC_NS, SESSION_KEY, SAMLEC_PREFIX));
                hdrblock->setAttribute(qMU, XML_ONE);
                hdrblock->setAttribute(qActor, m_actor.get());
                header->getUnknownXMLObjects().push_back(hdrblock);
                // Generate EncType and make it a child of SessionKey
                static const XMLCh ENC_TYPE[] = UNICODE_LITERAL_7(E,n,c,T,y,p,e);
                ElementProxy* encType = dynamic_cast<ElementProxy*>(m_anyBuilder.buildObject(SAMLEC_NS, ENC_TYPE, SAMLEC_PREFIX));
                static const XMLCh encTypeContent[] = { chLatin_a, chLatin_e, chLatin_s, chDigit_1, chDigit_2, chDigit_8, chDash, chLatin_c, chLatin_t, chLatin_s, chDash, chLatin_h, chLatin_m, chLatin_a, chLatin_c, chDash, chLatin_s, chLatin_h, chLatin_a, chDigit_1, chDash, chDigit_9, chDigit_6};
                encType->setTextContent(encTypeContent);
                hdrblock->getUnknownXMLObjects().push_back(encType);

                if (channel_bindings != NULL) {
                // Create cb:ChannelBindings header block.
                static const XMLCh CHANNEL_BINDINGS[] = UNICODE_LITERAL_15(C,h,a,n,n,e,l,B,i,n,d,i,n,g,s);
                static const XMLCh CB_PREFIX[] = UNICODE_LITERAL_2(c,b);
                static const XMLCh CB_NS[] = { chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon, chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon, chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chLatin_p, chLatin_r, chLatin_o, chLatin_t, chLatin_o, chLatin_c, chLatin_o, chLatin_l, chColon, chLatin_e, chLatin_x, chLatin_t, chColon, chLatin_c, chLatin_h, chLatin_a, chLatin_n, chLatin_n, chLatin_e, chLatin_l, chDash, chLatin_b, chLatin_i, chLatin_n, chLatin_d, chLatin_i, chLatin_n, chLatin_g, chNull };
                hdrblock = dynamic_cast<ElementProxy*>(m_anyBuilder.buildObject(CB_NS, CHANNEL_BINDINGS, CB_PREFIX));
                hdrblock->setAttribute(qMU, XML_ONE);
                hdrblock->setAttribute(qActor, m_actor.get());
                static const XMLCh cbType[] = UNICODE_LITERAL_4(T,y,p,e);
                auto_ptr_XMLCh m_cbtype("tls-server-end-point");
                hdrblock->setAttribute(xmltooling::QName(nullptr, cbType), m_cbtype.get());
                header->getUnknownXMLObjects().push_back(hdrblock);

                // Generate cb:ChannelBindings and make it a child of Extensions
                ElementProxy* cb = dynamic_cast<ElementProxy*>(m_anyBuilder.buildObject(CB_NS, CHANNEL_BINDINGS, CB_PREFIX));
                cb->setAttribute(xmltooling::QName(nullptr, cbType), m_cbtype.get());
                auto_ptr_XMLCh m_cbcontent(channel_bindings);
                cb->setTextContent(m_cbcontent.get());
                exten->getUnknownXMLObjects().push_back(cb);
                }

                // Create ecp:Request header.
                static const XMLCh IsPassive[] = UNICODE_LITERAL_9(I,s,P,a,s,s,i,v,e);
                hdrblock = dynamic_cast<ElementProxy*>(m_anyBuilder.buildObject(SAML20ECP_NS, saml1p::Request::LOCAL_NAME, SAML20ECP_PREFIX));
                hdrblock->setAttribute(qMU, XML_ONE);
                hdrblock->setAttribute(qActor, m_actor.get());
                if (!request->IsPassive())
                    hdrblock->setAttribute(xmltooling::QName(nullptr,IsPassive), XML_ZERO);
                hdrblock->getUnknownXMLObjects().push_back(request->getIssuer()->clone());
                if (request->getScoping() && request->getScoping()->getIDPList())
                    hdrblock->getUnknownXMLObjects().push_back(request->getScoping()->getIDPList()->clone());
                header->getUnknownXMLObjects().push_back(hdrblock);

                if (relayState && *relayState) {
                    // Create ecp:RelayState header.
                    static const XMLCh RelayState[] = UNICODE_LITERAL_10(R,e,l,a,y,S,t,a,t,e);
                    hdrblock = dynamic_cast<ElementProxy*>(m_anyBuilder.buildObject(SAML20ECP_NS, RelayState, SAML20ECP_PREFIX));
                    hdrblock->setAttribute(qMU, XML_ONE);
                    hdrblock->setAttribute(qActor, m_actor.get());
                    auto_ptr_XMLCh rs(relayState);
                    hdrblock->setTextContent(rs.get());
                    header->getUnknownXMLObjects().push_back(hdrblock);
                }

                try {
                    DOMElement* rootElement = nullptr;
                    if (cred) {
                        // Build a Signature.
                        Signature* sig = SignatureBuilder::buildSignature();
                        request->setSignature(sig);    
                        if (sigalg.first && sigalg.second)
                            sig->setSignatureAlgorithm(sigalg.second);
                        if (digalg.first && digalg.second) {
                            opensaml::ContentReference* cr = dynamic_cast<opensaml::ContentReference*>(sig->getContentReference());
                            if (cr) {
                                cr->setDigestAlgorithm(digalg.second);
                            }
                        }
                
                        // Sign message while marshalling.
                        vector<Signature*> sigs(1,sig);
                        rootElement = env->marshall((DOMDocument*)nullptr,&sigs,cred);

                    } else {
                        rootElement = env->marshall();
                    }

                    stringstream s;
                    s << *rootElement;

                    retstr = s.str();
                    
                    // long ret = genericResponse.sendResponse(s);
                
                    // Cleanup by destroying XML.
                    // NOTE THAT THIS CAUSES A CRASH RIGHT NOW!!!
                    // *** glibc detected *** /home/tfleury/develop/github.com/mech_saml_ec/gss-sample/.libs/lt-gss-server: free(): invalid pointer: 0x0000000001295108 ***
                    // delete env;
                }
                catch (XMLToolingException&) {
                }

            }
            sp->unlock();

        } 
        conf.term();
    }

    char* cstr = strdup(retstr.c_str());
    if (getenv("MECH_SAML_EC_DEBUG"))
        fprintf(stdout,"--- GETSAMLREQUEST2() RETURNING XML: ---\n%s\n",cstr);
    return cstr; //  Must free() returned char*
}

// Returns a vector of pointers to all SAML2 assertions found in
// a SAML2 response.  Any encrypted assertions are decrypted and also
// included in the vector.  Caller is responsible for memory allocated
// to all elements in the returned vector.
static vector<saml2::Assertion*> extractAssertions(const Response& resp,
                                                   const Application& app,
                                                   const SecurityPolicy& sp)
    {
    vector<saml2::Assertion*> retval;
    for ( size_t i = 0; i < resp.getAssertions().size(); ++i )
        retval.push_back(resp.getAssertions()[i]->cloneAssertion());

    const vector<saml2::EncryptedAssertion*>& encassertions =
        resp.getEncryptedAssertions();

    if ( ! encassertions.empty() )
        {
        CredentialResolver* cr = app.getCredentialResolver();
        if ( ! cr )
            {
            cerr << "Response contained encrypted assertion, "
                 <<  "but no CredentialResolver available." << endl;
            return retval;
            }

        for ( size_t i = 0; i < encassertions.size(); ++i )
            {
            try
                {
                Locker credlocker(cr);
                const EntityDescriptor* entity = nullptr;
                if ( sp.getIssuerMetadata() )
                  entity = dynamic_cast<const EntityDescriptor*>(
                    sp.getIssuerMetadata()->getParent());
                auto_ptr<MetadataCredentialCriteria> mcc(
                  sp.getIssuerMetadata() ?
                  new MetadataCredentialCriteria(*sp.getIssuerMetadata())
                  : nullptr);
                auto_ptr<XMLObject> tokenwrapper(encassertions[i]->decrypt(*cr,
                  app.getRelyingParty(entity)->getXMLString("entityID").second,
                  mcc.get()));
                saml2::Assertion* decassertion =
                  dynamic_cast<saml2::Assertion*>(tokenwrapper.get());

                if ( decassertion )
                    {
                    cerr << "Decrypted assertion." << endl;
                    if (getenv("MECH_SAML_EC_DEBUG")) {
                        DOMElement* assertionElement = decassertion->marshall();
                        stringstream s;
                        s << *assertionElement;
                        cerr << s.str().c_str() << endl;
                    }
                    retval.push_back(decassertion->cloneAssertion());
                    delete decassertion;
                    tokenwrapper.release();
                    }
                else
                    {
                    cerr << "Encrpyted assertion not decrypted." << endl;
                    }
                }
            catch ( exception& ex )
                {
                cerr << "Failed to decrypt assertion: " << ex.what() << endl;
                }
            }
       }

    return retval;
    }

// Filters a set of SAML2 assertions based on presence of a valid signature.
// The 'assertions' argument is modified in place to discard any invalidly
// signed signatures, which are then placed in the return vector.  A given
// assertion is valid only if all XMLSigningRule's in the 'policy' argument
// evaluate to true for it.  If the policy doesn't have any such rules,
// all assertions are considered invalid.
static vector<saml2::Assertion*> filterValidSignedAssertions(
    vector<saml2::Assertion*>& assertions, SecurityPolicy& policy)
    {
    vector<saml2::Assertion*> valid;
    vector<saml2::Assertion*> invalid;
    vector<const SecurityPolicyRule*> xml_rules;

    for ( size_t i = 0; i < policy.getRules().size(); ++i )
        if ( ! strcmp(policy.getRules()[i]->getType(), XMLSIGNING_POLICY_RULE) )
            xml_rules.push_back(policy.getRules()[i]);

    if ( xml_rules.empty() )
        {
        invalid = assertions;
        assertions.clear();
        cerr << "No XMLSigningRule's, all assertions deemed invalid" << endl;
        return invalid;
        }

    for ( size_t i = 0; i < assertions.size(); ++i )
        {
        bool is_valid = true;

        for ( size_t j = 0; j < xml_rules.size(); ++j )
            {
            try
                {
                is_valid = xml_rules[j]->evaluate(*(assertions[i]), 0, policy);
                }
            catch ( exception& e )
                {
                is_valid = false;
                cerr << "Assertion signature failed verification: "
                     << e.what() << endl;
                }
            if ( ! is_valid ) break;
            }

        if ( is_valid )
            {
            cerr << "Signature on assertion verified" << endl;
            valid.push_back(assertions[i]);
            }
        else
            {
            cerr << "Filtered invalidly signed assertion" << endl;
            invalid.push_back(assertions[i]);
            }
        }

    assertions = valid;
    return invalid;
    }

extern "C" int verifySAMLResponse(const char* saml, int len, char** initiator_name,
                                  char ** session_not_or_after, char **generated_key)
{
    int retbool = 1; // FIXME: Defaulting to successful verification is dangerous.
    string initiatorName = "";

    XMLToolingConfig::getConfig().log_config("DEBUG");
    Category& log = Category::getInstance(SHIBSP_LOGCAT".verifySAMLResponse");

    string samlstr(saml, len);
    if (getenv("MECH_SAML_EC_DEBUG"))
        fprintf(stdout,"--- VERIFYSAMLRESPONSE() GOT XML: ---\n%s\n",samlstr.c_str());

    // Initialization code taken from resolvertest.cpp::main()
    SPConfig& conf = getConf();
    if (conf.init()) {
        if (conf.instantiate()) {
            ServiceProvider* sp = conf.getServiceProvider();
            sp->lock();
            const Application* app = sp->getApplication("default");
            if (app) {
                // Get the AssertionConsumerService
                const Handler* ACS=nullptr;
                ACS = app->getAssertionConsumerServiceByProtocol(SAML20P_NS,SAML20_BINDING_PAOS);
                if (!ACS) {
                    cerr << "Unable to locate PAOS response endpoint." << endl;
                    retbool = 0;
                }

                if (retbool) {
                    MetadataProvider* m = app->getMetadataProvider();
                    Locker mlocker(m);
                    TrustEngine* trust = app->getTrustEngine();
                    xmltooling::QName idprole(samlconstants::SAML20MD_NS,IDPSSODescriptor::LOCAL_NAME);
                    SecurityPolicy policy(m,&idprole,trust,false);
                    // Create policy rule list, a combination of code from 
                    // opensaml-2.5/samltest/binding.h setUp(), lines 86-88
                    // shibboleth-2.5/shibsp/security/SecurityPolicy.cpp, lines 35-37
                    // SAML2POSTTEST.h line 38
                    vector<const SecurityPolicyRule*> rules =
                        app->getServiceProvider().getPolicyRules(app->getString("policyId").second);
                    rules.push_back(SAMLConfig::getConfig().SecurityPolicyRuleManager.newPlugin(BEARER_POLICY_RULE, nullptr));
                    policy.getRules().assign(rules.begin(),rules.end());
                    /*
                    vector<const SecurityPolicyRule*>::iterator it;
                    for (it = rules.begin(); it < rules.end(); it++) {
                        cerr << "rule = " << (*it)->getType() << endl;
                    }
                    */

                    // Taken from util/resolvertest.cpp and SAML2ECPDecoder::decode()
                    try {
                        istringstream samlstream(samlstr);
                       
                        // Taken from SAML2ECPDecoder::decode()
                        cerr << "parsing samlstream..." << endl;
                        DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(samlstream);
                        cerr << "samlstream parsing succeeded!" << endl;
                        XercesJanitor<DOMDocument> docjan(doc);
                        auto_ptr<XMLObject> token(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
                        docjan.release();

                        Envelope* env = dynamic_cast<Envelope*>(token.get());
                        if (env) {
                            SchemaValidators.validate(env);

                            Body* body = env->getBody();
                            if (body && body->hasChildren()) {
                                Response* response = dynamic_cast<Response*>(body->getUnknownXMLObjects().front());
                                if (response) {
                                    // Run through the policy at two layers.
                                    /*
                                    extractMessageDetails(*env, genericRequest, samlconstants::SAML20P_NS, policy);
                                    policy.evaluate(*env, &genericRequest);
                                    policy.reset(true);
                                    extractMessageDetails(*response, genericRequest, samlconstants::SAML20P_NS, policy);
                                    policy.evaluate(*response, &genericRequest);
                                    */
                                    // Don't bother with extractMessageDetails(*env,...) since env is not a SAML20P_NS
                                    // Instead, call SAML2MessageDecoder::extractMessageDetails(*response,...)
                                    const xmltooling::QName& q = response->getElementQName();
                                    if (XMLString::equals(q.getNamespaceURI(), samlconstants::SAML20P_NS)) {
                                        try {
                                            const saml2::RootObject& samlRoot = dynamic_cast<const saml2::RootObject&>(*response);
                                            vector<saml2::Assertion*> assertions =
                                                extractAssertions(dynamic_cast<const Response&>(samlRoot), *app, policy);

                                            policy.setMessageID(samlRoot.getID());
                                            policy.setIssueInstant(samlRoot.getIssueInstantEpoch());

                                            const Issuer* issuer = samlRoot.getIssuer();
                                            if (issuer) {
                                                policy.setIssuer(issuer);
                                            } else if (XMLString::equals(q.getLocalPart(), Response::LOCAL_NAME)) {
                                                // No issuer in the message, so we have to try the Response approach.
                                                if (!assertions.empty()) {
                                                    issuer = assertions.front()->getIssuer();
                                                    if (issuer) {
                                                        policy.setIssuer(issuer);
                                                    }
                                                }
                                            }
                                            if (!issuer) {
                                                cerr << "Issuer identity not extracted!" << endl;
                                                retbool = 0;
                                            }

                                            if (retbool) {
                                                auto_ptr_char iname(issuer->getName());
                                                cout << "issuer = " << iname.get() << endl;

                                                if (policy.getIssuerMetadata()) {
                                                    cerr << "metadata for issuer already set, leaving in place." << endl;
                                                    // return;
                                                }

                                                if (policy.getMetadataProvider() && policy.getRole()) {
                                                    if (issuer->getFormat() && !XMLString::equals(issuer->getFormat(), 
                                                                                                  NameIDType::ENTITY)) {
                                                        cerr << "non-system entity issuer, skipping metadata lookup!" << endl;
                                                        // return;
                                                    }

                                                    cerr << "searching metadata for message issuer... ";
                                                    MetadataProvider::Criteria& mc = policy.getMetadataProviderCriteria();
                                                    mc.entityID_unicode = issuer->getName();
                                                    mc.role = policy.getRole();
                                                    mc.protocol = samlconstants::SAML20P_NS;
                                                    pair<const EntityDescriptor*,const RoleDescriptor*> entity = 
                                                        policy.getMetadataProvider()->getEntityDescriptor(mc);
                                                    if (!entity.first) {
                                                        auto_ptr_char temp(issuer->getName());
                                                        cerr << "no metadata found, can't establish identity of issuer (" <<
                                                                temp.get() << ")" << endl;
                                                        retbool = 0;
                                                    }
                                                    else if (!entity.second) {
                                                        cerr << "unable to find compatible role (" << 
                                                                policy.getRole()->toString().c_str() << ") in metadata" << endl;
                                                        retbool = 0;
                                                    } else {
                                                        policy.setIssuerMetadata(entity.second);
                                                        cerr << "Done!" << endl;
                                                    }

                                                    vector<saml2::Assertion*> invalid_assertions =
                                                        filterValidSignedAssertions(assertions, policy);
                                                    for_each(invalid_assertions.begin(), invalid_assertions.end(), xmltooling::cleanup<saml2::Assertion>());

                                                    // Attempt to extract local-login-user attribute
                                                    // Taken from resolvertest.cpp
                                                    if (retbool) {
                                                        if (!assertions.empty()) {
                                                            saml2::Assertion* a2 = assertions.front();
                                                            if (!a2->getAuthnStatements().empty()) {
                                                                // Draft wording refers to one assertion with one AuthnStatement within it. TODO VSY: check this and fail if it is not true?
                                                                saml2::AuthnStatement* authnst = a2->getAuthnStatements().front();
                                                                if (authnst && authnst->getSessionNotOnOrAfter() != NULL) {
                                                                    char *tmp = xercesc::XMLString::transcode(authnst->getSessionNotOnOrAfter()->getFormattedString());
                                                                    *session_not_or_after = strdup(tmp);
                                                                    xercesc::XMLString::release(&tmp);
                                                                }
                                                            }
                                                            saml2::Advice* advice = a2->getAdvice();
                                                            if (advice != nullptr) {
                                                                // TODO VSY: Get GeneratedKey content and return it instead of whole Advice XML
                                                                DOMElement* adviceElement = advice->marshall();
                                                                stringstream s;
                                                                s << *adviceElement;
                                                                *generated_key = strdup(s.str().c_str());
                                                            }
                                                            const XMLCh* protocol = samlconstants::SAML20P_NS;
                                                            saml2::NameID* v2name = a2->getSubject()?a2->getSubject()->getNameID():nullptr;
                                                            vector<const opensaml::Assertion*> tokens;
                                                            tokens.assign(assertions.begin(),assertions.end());

                                                            LocalResolver lr(nullptr,nullptr);
                                                            ctx = lr.resolveAttributes(
                                                                *app,entity.second,protocol,nullptr,v2name,
                                                                    nullptr,nullptr,&tokens);
                                                            // auto_ptr<ResolutionContext> wrapper(ctx); NOTE: ctx now static to enable later retrieval of attributes
                                                            if (v2name != nullptr) {
                                                                char *tmp;
                                                                initiatorName += (tmp = xercesc::XMLString::transcode(v2name->getName()));
                                                                xercesc::XMLString::release(&tmp);
                                                                initiatorName += "!";
                                                                initiatorName += v2name->getFormat()?(tmp = xercesc::XMLString::transcode(v2name->getFormat())):"";
                                                                xercesc::XMLString::release(&tmp);
                                                                initiatorName += "!";
                                                                initiatorName += v2name->getNameQualifier()?(tmp = xercesc::XMLString::transcode(v2name->getNameQualifier())):"";
                                                                xercesc::XMLString::release(&tmp);
                                                                initiatorName += "!";
                                                                initiatorName += v2name->getSPNameQualifier()?(tmp = xercesc::XMLString::transcode(v2name->getSPNameQualifier())):"";
                                                                xercesc::XMLString::release(&tmp);
                                                                initiatorName += "!";
                                                                initiatorName += v2name->getSPProvidedID()?(tmp = xercesc::XMLString::transcode(v2name->getSPProvidedID())):"";
                                                                xercesc::XMLString::release(&tmp);
                                                            }
                                                        } else {
                                                            cerr << "no valid assertions available to inspect for attribute mapped to local-login-user" << endl;
                                                            retbool = 0;
                                                        }
                                                    }
                                                }
                                            }
                                            for_each(assertions.begin(), assertions.end(), xmltooling::cleanup<saml2::Assertion>());
                                        } catch (bad_cast&) {
                                            cerr << "caught a bad_cast while extracting message details" << endl;
                                        }
                                    } else { // Message is not SAML20P_NS - problem!
                                        retbool = 0;
                                    }
                                    // End SAML2MessageDecoder::extractMessageDetails(*response,...)

                                    if (retbool) {
                                        try {
                                            cerr << "Evaluating SecurityPolicy rules on Response" << endl;
                                            for ( size_t i = 0; i < policy.getRules().size(); ++i )
                                                {
                                                string rule_type = policy.getRules()[i]->getType();
                                                if ( policy.getRules()[i]->evaluate(*response, nullptr, policy) )
                                                    cerr << "SecurityPolicyRule '" << rule_type << "' passed." << endl;
                                                else
                                                    cerr << "SecurityPolicyRule '" << rule_type << "' ignored." << endl;
                                                }
                                        } catch (exception& ex) {
                                            retbool = 0;
                                            cerr << "Caught exception evaluating SecurityPolicy on Response:"<< ex.what() << endl;
                                        }
                                    }

                                    if (retbool) {
                                        // Check destination URL.
                                        auto_ptr_char dest(response->getDestination());
                                        if (response->getSignature() && (!dest.get() || !*(dest.get()))) {
                                            cerr << "Signed SAML message missing Destination attribute!" << endl;
                                            // return 0;
                                            retbool = 0;
                                        }
                                    }

                                    // Check for RelayState header.
                                    // Do we need to do something "useful" with the RelayState?
                                    if ((retbool) && (env->getHeader())) {
                                        string relayState;
                                        static const XMLCh RelayState[] = UNICODE_LITERAL_10(R,e,l,a,y,S,t,a,t,e);
                                        const vector<XMLObject*>& blocks = const_cast<const Header*>(env->getHeader())->getUnknownXMLObjects();
                                        vector<XMLObject*>::const_iterator h =
                                            find_if(blocks.begin(), blocks.end(), hasQName(xmltooling::QName(samlconstants::SAML20ECP_NS, RelayState)));
                                        const ElementProxy* ep = dynamic_cast<const ElementProxy*>(h != blocks.end() ? *h : nullptr);
                                        if (ep) {
                                            auto_ptr_char rs(ep->getTextContent());
                                            if (rs.get())
                                                relayState = rs.get();
                                        }
                                        cout << "relayState = " << relayState << endl;
                                    }

                                    token.release();
                                    body->detach(); // frees Envelope
                                    response->detach();   // frees Body
                                }
                            }
                        } else {
                            cerr << "-----" << endl << "Decoded message was not a SOAP 1.1 Envelope" << endl << "-----" << endl;
                        }

                        /*
                        DOMElement *elem = doc->getDocumentElement();
                        stringstream s;
                        s << *elem;
                        cerr << "-----" << endl << "s = " << s << endl << "-----" << endl;
                        */


                    } catch (exception & ex) {
                        retbool = 0;
                        cerr << "Caught exception: " << ex.what() << endl;
                    }

                // XXX This is here to force a cleanup of any role the
                // SecurityPolicy object allocated, which really seems
                // like a bug in the SAML library's implementation of
                // the SecurityPolicy destructor for not cleaning it up.
                policy.setRole(nullptr);
                }
            }
            sp->unlock();

        } 
        conf.term();
    }

    if (!initiatorName.empty()) {
      *initiator_name = strdup(initiatorName.c_str());
    }

    return retbool;
}

// 1 on success; 0 on not found
extern "C" int getSAMLAttribute(const char* attrib, char** value)
{
    string localValue = "";

    *value = NULL;

    if (ctx == nullptr)
        return 0;

    for (vector<shibsp::Attribute*>::const_iterator a = ctx->getResolvedAttributes().begin(); 
         a != ctx->getResolvedAttributes().end(); 
         ++a) {
        for (vector<string>::const_iterator s = (*a)->getAliases().begin(); 
             s != (*a)->getAliases().end(); 
             ++s) {
            if (s->compare(attrib) == 0) {
                for (vector<string>::const_iterator v=(*a)->getSerializedValues().begin();
                     v != (*a)->getSerializedValues().end(); 
                     ++v) {
                    if (v != (*a)->getSerializedValues().begin())
                        localValue += ";";
                    localValue += *v;
                }
            }
        }
    }

    if (localValue.empty())
        return 0;

    // TODO: check for allocation failure here and elsewhere.
    *value = strdup(localValue.c_str());
    return 1;
}
