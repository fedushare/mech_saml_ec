#include <shibsp/AbstractSPRequest.h>
#include <shibsp/Application.h>
#include <shibsp/SPConfig.h>
#include <shibsp/ServiceProvider.h>
#include <shibsp/handler/Handler.h>
#include <saml/SAMLConfig.h>
#include <saml/saml1/core/Protocols.h>
#include <saml/saml2/core/Protocols.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <saml/util/SAMLConstants.h>
#include <xercesc/dom/DOM.hpp>
#include <xmltooling/exceptions.h>
#include <xmltooling/soap/SOAP.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/impl/AnyElement.h>
#include <xmltooling/util/XMLHelper.h>
#include <xmltooling/util/XMLConstants.h>
#include <iostream>
#include <sstream>

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


extern "C" const char* getSAMLRequest2(void)
{
    string retstr = "";

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

                MetadataProvider* m = app->getMetadataProvider();
                pair<const EntityDescriptor*,const RoleDescriptor*> entity = 
                    pair<const EntityDescriptor*,const RoleDescriptor*>(nullptr,nullptr);
                const IDPSSODescriptor* role = nullptr;
                const EndpointType* ep = nullptr;
                const MessageEncoder* encoder = nullptr;

                Locker mlocker(m);

                // Taken from constructor of SAML2SessionInitiator
                // BUT, e is "const DOMElement*" and I have no idea what
                // actually calls the constructor, so no idea what 'e' is.
                // Thus the encoder may be incomplete.
                DOMElement* e;
                try {
                    encoder = SAMLConfig::getConfig().MessageEncoderManager.newPlugin(SAML20_BINDING_PAOS, pair<const DOMElement*,const XMLCh*>(e,nullptr));
                } catch (exception & ex) {
                }
                
                // Now in doRequest

                /*
                preserveRelayState(app, httpResponse, relayState);
                 */

                // Get the AssertionConsumerService
                const Handler* ACS=nullptr;
                ACS = app->getAssertionConsumerServiceByProtocol(SAML20P_NS,SAML20_BINDING_PAOS);
                if (!ACS)
                    throw XMLToolingException("Unable to locate PAOS response endpoint.");

                // Build up AuthnRequest section of the SOAP message
                auto_ptr<AuthnRequest> request(AuthnRequestBuilder::buildAuthnRequest());
                
                // NEED SOME WAY TO GET handlerURL for setAssertionConsumerServiceURL()
                //     string ACSloc = request.getHandlerURL(target.c_str());
                //     const char* acsLocation = ACSloc.c_str();
                // For now, set to a static string
                auto_ptr_XMLCh acsLocation("https://test.cilogon.org/Shibboleth.sso/SAML2/ECP");
                request->setAssertionConsumerServiceURL(acsLocation.get());

                Issuer* issuer = IssuerBuilder::buildIssuer();
                request->setIssuer(issuer);
                issuer->setName(app->getRelyingParty(entity.first)->getXMLString("entityID").second);

                auto_ptr_XMLCh acsBinding((ACS->getString("Binding")).second);
                request->setProtocolBinding(acsBinding.get());

                NameIDPolicy* namepol = NameIDPolicyBuilder::buildNameIDPolicy();
                namepol->AllowCreate(true);
                request->setNameIDPolicy(namepol);

                // Debugging - Print AuthnRuquest section to stdout
                XMLObject* requestobj = request.get();
                // cout << *requestobj << endl;
                // xercesc::DOMElement* dom = requestobj->getDOM();

             
                // Taken from AbstractHandler.cpp
                // sendMessage(*encoder,requestobj,relayState.c_str(),dest.get()[=nullptr],
                //             role[=nullptr],app,httpResponse,false);
                const EntityDescriptor* entity2 = nullptr;
                const PropertySet* relyingParty = app->getRelyingParty(entity2);
                pair<bool,const char*> flag = relyingParty->getString("signing");
                // Make an unsigned request
                // return encoder.encode(httpResponse,requestobj,dest.get()[=nullptr],
                //                       entity2[=nullptr],relayState.c_str(),&app)
                // Call into opensaml's SAML2ECPEncoder.cpp
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

                // NEED relaystate for the following section
                /*
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
                */

                try {
                    DOMElement* rootElement = nullptr;
                    rootElement = env->marshall();

                    stringstream s;
                    s << *rootElement;

                    retstr = s.str();
                    cout << endl << "Sending the following XML:" 
                         << endl << retstr << endl;
                    
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

    return retstr.c_str();
}

extern "C" int verifySAMLResponse(const char* saml, int len) 
{
    int retbool = 1;


    return retbool;
}

