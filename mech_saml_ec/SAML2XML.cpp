#include <shibsp/Application.h>
#include <shibsp/SPConfig.h>
#include <shibsp/ServiceProvider.h>
#include <saml/SAMLConfig.h>
#include <saml/saml2/core/Protocols.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <saml/util/SAMLConstants.h>
#include <xercesc/dom/DOM.hpp>
#include <xmltooling/exceptions.h>
#include <xmltooling/XMLToolingConfig.h>

using namespace shibsp;
using namespace opensaml;
using namespace opensaml::saml2;
using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace xercesc;
using namespace xmltooling;
using namespace std;

const char* getSAMLRequest2(
    bool holderOfKey=false, 
    bool channelBinding=false)
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
                Locker mlocker(m);

                // Taken from constructor of SAML2SessionInitiator
                // BUT, e is "const DOMElement*" and I have no idea what
                // actually calls the constructor, so no idea what 'e' is.
                MessageEncoder* m_ecp;
                DOMElement* e;
                try {
                    m_ecp = SAMLConfig::getConfig().MessageEncoderManager.newPlugin(samlconstants::SAML20_BINDING_PAOS, pair<const DOMElement*,const XMLCh*>(e,nullptr));
                } catch (exception & ex) {
                }
                
                // Now in doRequest

                /*
                preserveRelayState(app, httpResponse, relayState);
                 */
                auto_ptr<AuthnRequest> req(AuthnRequestBuilder::buildAuthnRequest());
                /*
                const Handler* ACS=nullptr;
                ACS = app->getAssertionConsumerServiceByProtocol(samlconstants::SAML20P_NS,samlconstants::SAML20_BINDING_PAOS);
                if (!ACS)
                    throw XMLToolingException("Unable to locate PAOS response endpoint.");
                */
            }
            sp->unlock();

        } 
        conf.term();
    }

    return retstr.c_str();
}
