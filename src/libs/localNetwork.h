#ifndef KYTY_LIBS_LOCAL_NETWORK_H_
#define KYTY_LIBS_LOCAL_NETWORK_H_

#include <string>
#include <vector>
#include <utility>

namespace Libs::LocalNetwork {
struct Response {
    bool completed = false;
    int status = 0;
    std::string headers;
    std::string body;
};
bool Enabled();
Response Exchange(const std::string& method, const std::string& url,
                  const void* data, size_t size,
                  const std::vector<std::pair<std::string, std::string>>& headers = {});
}
#endif
