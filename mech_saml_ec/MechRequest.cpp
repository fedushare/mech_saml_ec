#include <xmltooling/io/GenericRequest.h>
#include <string>

#ifndef XMLTOOLING_NO_XMLSEC
#  include <xsec/enc/XSECCryptoX509.hpp>
#endif

using namespace std;

namespace xmltooling {
    class MechRequest : public GenericRequest {
        const char* m_input;
        long m_inputlen;
#ifndef XMLTOOLING_NO_XMLSEC
        vector<XSECCryptoX509*> 
#else
        vector<string>
#endif
        m_dummy;
    public:
        MechRequest(const char* input, long len) : 
                    m_input(input), m_inputlen(len) {}
        virtual ~MechRequest() {}

        const char* getScheme() const { return nullptr; }

        bool isSecure() const {
          // I don't think the mech can assume a secure transport?
          return false;
        }

        const char* getHostname() const {
          // Do we know the acceptor name?
          return nullptr;
        }

        int getPort() const { return -1; }

        bool isDefaultPort() const { return false; }

        string getContentType() const {
          return "application/vnd.paos+xml";
        }
          
        long getContentLength() const {
          return m_inputlen;
        }

        const char* getRequestBody() const {
          return m_input;
        }

        const char* getParameter(const char* name) const { return nullptr; }

        vector<const char*>::size_type getParameters(
            const char* name, vector<const char*>& values
        ) const { return 0; }

        string getRemoteUser() const { return ""; }

        string getRemoteAddr() const { return ""; }

        const 
#ifndef XMLTOOLING_NO_XMLSEC
        vector<XSECCryptoX509*>& 
#else
        vector<string>&
#endif
        getClientCertificates() const {
            return m_dummy;
        }

    };
};
