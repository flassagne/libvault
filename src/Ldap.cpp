#include "VaultClient.h"

#include <nlohmann/json.hpp>

Ldap::Ldap(std::string login, std::string password)
    : login_{login}, password_{password} {}

optional<std::string> Ldap::authenticate(const VaultClient &client) {
  nlohmann::json j;
  j = nlohmann::json::object();
  j["password"] = password_;

  auto response = client.getHttpClient().post(getUrl(client, "/" + password_),
                                              "", "", j.dump());

  if (HttpClient::is_success(response)) {
    return nlohmann::json::parse(response.value().body)["auth"]["client_token"];
  } else {
    return std::experimental::nullopt;
  }
}

std::string Ldap::getUrl(const VaultClient &client, const std::string &path) {
  return client.getUrl("/v1/auth/ldap/login", path);
}
