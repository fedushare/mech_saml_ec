#include <shibsp/AbstractSPRequest.h>
#include <shibsp/Application.h>
#include <shibsp/SPConfig.h>
#include <shibsp/ServiceProvider.h>
#include <shibsp/attribute/Attribute.h>
#include <shibsp/attribute/resolver/ResolutionContext.h>
#include <shibsp/handler/Handler.h>
#include <saml/SAMLConfig.h>
#include <saml/saml1/core/Assertions.h>
#include <saml/saml1/core/Protocols.h>
#include <saml/saml2/core/Assertions.h>
#include <saml/saml2/core/Protocols.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <saml/util/SAMLConstants.h>
#include <xercesc/dom/DOM.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/exceptions.h>
#include <xmltooling/soap/SOAP.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/impl/AnyElement.h>
#include <xmltooling/util/ParserPool.h>
#include <xmltooling/util/XMLHelper.h>
#include <xmltooling/util/XMLConstants.h>
#include <iostream>
#include <sstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

using namespace opensaml;
using namespace opensaml::saml2;
using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace samlconstants;
using namespace shibsp;
using namespace soap11;
using namespace xercesc;
using namespace xmlconstants;
using namespace xmltooling;
using namespace std;

// Taken from http://stackoverflow.com/questions/504810/
const char* getfqdn() 
{
    const char* retstr;
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

extern "C" char* getSAMLRequest2(void)
{
    string retstr = "";

    // Initialization code taken from resolvertest.cpp::main()
    SPConfig& conf = SPConfig::getConfig();
    conf.setFeatures(
        SPConfig::Metadata |
        SPConfig::Trust |
        SPConfig::AttributeResolution |
        SPConfig::Credentials |
        SPConfig::OutOfProcess |
        SPConfig::Caching |
        SPConfig::Handlers
    );
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
                DOMElement* e;
                const MessageEncoder* encoder = nullptr;
                try {
                    encoder = SAMLConfig::getConfig().MessageEncoderManager.newPlugin(SAML20_BINDING_PAOS, pair<const DOMElement*,const XMLCh*>(e,nullptr));
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
                const char* fqdn = getfqdn();
                string resourcestr;
                const char* resource;
                resourcestr = "https://" + string(fqdn) + "/";
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

                XMLObject* requestobj = request.get();
             
                // Taken from AbstractHandler.cpp
                // sendMessage(*encoder,requestobj,relayState.c_str(),dest.get()[=nullptr],
                //             role[=nullptr],app,httpResponse,false);
                const EntityDescriptor* entity2 = nullptr;
                const PropertySet* relyingParty = app->getRelyingParty(entity2);
                pair<bool,const char*> flag = relyingParty->getString("signing");
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
                    rootElement = env->marshall();

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
    fprintf(stderr,"--- GETSAMLREQUEST2() RETURNING XML: ---\n%s\n",cstr);
    return cstr; //  Must free() returned char*
}

extern "C" int verifySAMLResponse(const char* saml, int len) 
{
    int retbool = 1;

    fprintf(stderr,"--- VERIFYSAMLRESPONSE() GOT XML: ---\n%s\n",saml);

    // Initialization code taken from resolvertest.cpp::main()
    SPConfig& conf = SPConfig::getConfig();
    conf.setFeatures(
        SPConfig::Metadata |
        SPConfig::Trust |
        SPConfig::AttributeResolution |
        SPConfig::Credentials |
        SPConfig::OutOfProcess |
        SPConfig::Caching |
        SPConfig::Handlers
    );
    if (conf.init()) {
        if (conf.instantiate()) {
            ServiceProvider* sp = conf.getServiceProvider();
            sp->lock();
            const Application* app = sp->getApplication("default");
            if (app) {
                // Taken from util/resolvertest.cpp
                try {
                    ResolutionContext* ctx;
                    string samlstr(saml);
                    istringstream samlstream(samlstr);
                    DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(samlstream);
                    XercesJanitor<DOMDocument> docjan(doc);
                    auto_ptr<XMLObject> token(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
                    docjan.release();

                    DOMElement *elem = doc->getDocumentElement();
                    stringstream s;
                    s << *elem;
                    cerr << "-----" << endl << "s = " << s << endl << "-----" << endl;



                } catch (exception & ex) {
                }

            }
            sp->unlock();

        } 
        conf.term();
    }

    return retbool;
}

