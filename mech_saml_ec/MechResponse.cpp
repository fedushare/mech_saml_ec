#include <xmltooling/io/GenericResponse.h>
#include <saml/exceptions.h>
#include <string>
#include <iostream>

using namespace std;

namespace xmltooling {
    class XMLTOOL_API MechResponse : public GenericResponse {
    public:
        MechResponse() {}
        virtual ~MechResponse() {}

        void setContentType(const char* type=nullptr) {}

        virtual long sendResponse(istream& in) {
            string sink;
            char buf[1024];
            while (in) {
                in.read(buf,1024);
                sink.append(buf,in.gcount());
            }
            return 0;
        }

        virtual long sendError(istream& inputStream) {
            // Encoders don't send errors.
            throw IOException("...");
        }

        virtual long sendResponse(istream& inputStream, long status) {
            // No transport awareness allowed, so not supported.
            throw IOException("...");
        }
    };
};
