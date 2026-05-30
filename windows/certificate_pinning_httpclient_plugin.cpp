#include "certificate_pinning_httpclient_plugin.h"

#include <windows.h>
#include <wincrypt.h>
#include <winhttp.h>

#include <flutter/encodable_value.h>
#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>

#include <memory>
#include <string>
#include <thread>
#include <variant>
#include <vector>

namespace certificate_pinning_httpclient {
namespace {

constexpr int kFetchCertificatesTimeoutMs = 3000;

class WinHttpHandle {
 public:
  explicit WinHttpHandle(HINTERNET handle = nullptr) : handle_(handle) {}

  ~WinHttpHandle() {
    if (handle_) {
      WinHttpCloseHandle(handle_);
    }
  }

  WinHttpHandle(const WinHttpHandle&) = delete;
  WinHttpHandle& operator=(const WinHttpHandle&) = delete;

  HINTERNET get() const { return handle_; }

 private:
  HINTERNET handle_;
};

std::wstring Utf8ToWide(const std::string& value) {
  if (value.empty()) {
    return std::wstring();
  }

  const int size = MultiByteToWideChar(CP_UTF8, 0, value.data(),
                                       static_cast<int>(value.size()), nullptr,
                                       0);
  if (size <= 0) {
    return std::wstring();
  }

  std::wstring wide(static_cast<size_t>(size), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, value.data(),
                      static_cast<int>(value.size()), wide.data(), size);
  return wide;
}

std::string LastErrorMessage(const std::string& prefix) {
  return prefix + " failed with Windows error " + std::to_string(GetLastError());
}

const flutter::EncodableMap* ArgumentsAsMap(
    const flutter::EncodableValue* arguments) {
  if (!arguments ||
      !std::holds_alternative<flutter::EncodableMap>(*arguments)) {
    return nullptr;
  }
  return &std::get<flutter::EncodableMap>(*arguments);
}

bool ExtractUrl(const flutter::EncodableValue* arguments, std::string* url) {
  const flutter::EncodableMap* map = ArgumentsAsMap(arguments);
  if (!map) {
    return false;
  }

  const auto iterator = map->find(flutter::EncodableValue("url"));
  if (iterator == map->end() ||
      !std::holds_alternative<std::string>(iterator->second)) {
    return false;
  }

  *url = std::get<std::string>(iterator->second);
  return true;
}

std::vector<std::vector<uint8_t>> CertificatesFromChain(
    PCCERT_CHAIN_CONTEXT chain_context) {
  std::vector<std::vector<uint8_t>> certificates;
  if (!chain_context) {
    return certificates;
  }

  for (DWORD chain_index = 0; chain_index < chain_context->cChain;
       ++chain_index) {
    const PCERT_SIMPLE_CHAIN simple_chain =
        chain_context->rgpChain[chain_index];
    if (!simple_chain) {
      continue;
    }

    for (DWORD element_index = 0; element_index < simple_chain->cElement;
         ++element_index) {
      const PCERT_CHAIN_ELEMENT element =
          simple_chain->rgpElement[element_index];
      if (!element || !element->pCertContext) {
        continue;
      }

      const PCCERT_CONTEXT cert_context = element->pCertContext;
      certificates.emplace_back(
          cert_context->pbCertEncoded,
          cert_context->pbCertEncoded + cert_context->cbCertEncoded);
    }
  }

  return certificates;
}

std::vector<std::vector<uint8_t>> CertificateFromContext(
    PCCERT_CONTEXT cert_context) {
  if (!cert_context) {
    return {};
  }

  return {std::vector<uint8_t>(
      cert_context->pbCertEncoded,
      cert_context->pbCertEncoded + cert_context->cbCertEncoded)};
}

std::vector<std::vector<uint8_t>> FetchHostCertificates(
    const std::string& url,
    std::string* error_message) {
  const std::wstring wide_url = Utf8ToWide(url);
  if (wide_url.empty()) {
    *error_message = "Invalid URL encoding";
    return {};
  }

  URL_COMPONENTS components = {};
  components.dwStructSize = sizeof(components);
  components.dwSchemeLength = static_cast<DWORD>(-1);
  components.dwHostNameLength = static_cast<DWORD>(-1);
  components.dwUrlPathLength = static_cast<DWORD>(-1);
  components.dwExtraInfoLength = static_cast<DWORD>(-1);

  if (!WinHttpCrackUrl(wide_url.c_str(), 0, 0, &components)) {
    *error_message = LastErrorMessage("WinHttpCrackUrl");
    return {};
  }

  if (components.nScheme != INTERNET_SCHEME_HTTPS) {
    *error_message = "Only HTTPS URLs are supported";
    return {};
  }

  std::wstring host(components.lpszHostName, components.dwHostNameLength);
  std::wstring path(components.lpszUrlPath, components.dwUrlPathLength);
  if (components.dwExtraInfoLength > 0) {
    path.append(components.lpszExtraInfo, components.dwExtraInfoLength);
  }
  if (path.empty()) {
    path = L"/";
  }

  WinHttpHandle session(WinHttpOpen(
      L"certificate_pinning_httpclient/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
  if (!session.get()) {
    *error_message = LastErrorMessage("WinHttpOpen");
    return {};
  }

  WinHttpSetTimeouts(session.get(), kFetchCertificatesTimeoutMs,
                     kFetchCertificatesTimeoutMs, kFetchCertificatesTimeoutMs,
                     kFetchCertificatesTimeoutMs);

  WinHttpHandle connection(
      WinHttpConnect(session.get(), host.c_str(), components.nPort, 0));
  if (!connection.get()) {
    *error_message = LastErrorMessage("WinHttpConnect");
    return {};
  }

  WinHttpHandle request(WinHttpOpenRequest(
      connection.get(), L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER,
      WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
  if (!request.get()) {
    *error_message = LastErrorMessage("WinHttpOpenRequest");
    return {};
  }

  WinHttpSetTimeouts(request.get(), kFetchCertificatesTimeoutMs,
                     kFetchCertificatesTimeoutMs, kFetchCertificatesTimeoutMs,
                     kFetchCertificatesTimeoutMs);

  if (!WinHttpSendRequest(request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                          WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
    *error_message = LastErrorMessage("WinHttpSendRequest");
    return {};
  }

  if (!WinHttpReceiveResponse(request.get(), nullptr)) {
    *error_message = LastErrorMessage("WinHttpReceiveResponse");
    return {};
  }

  PCCERT_CHAIN_CONTEXT chain_context = nullptr;
  DWORD chain_context_size = sizeof(chain_context);
  if (WinHttpQueryOption(request.get(), WINHTTP_OPTION_SERVER_CERT_CHAIN_CONTEXT,
                         &chain_context, &chain_context_size)) {
    std::vector<std::vector<uint8_t>> certificates =
        CertificatesFromChain(chain_context);
    CertFreeCertificateChain(chain_context);
    return certificates;
  }

  PCCERT_CONTEXT cert_context = nullptr;
  DWORD cert_context_size = sizeof(cert_context);
  if (WinHttpQueryOption(request.get(), WINHTTP_OPTION_SERVER_CERT_CONTEXT,
                         &cert_context, &cert_context_size)) {
    std::vector<std::vector<uint8_t>> certificates =
        CertificateFromContext(cert_context);
    CertFreeCertificateContext(cert_context);
    return certificates;
  }

  *error_message = LastErrorMessage("WinHttpQueryOption SERVER_CERT_CONTEXT");
  return {};
}

flutter::EncodableValue ToEncodableCertificateList(
    const std::vector<std::vector<uint8_t>>& certificates) {
  flutter::EncodableList encoded_certificates;
  encoded_certificates.reserve(certificates.size());
  for (const auto& certificate : certificates) {
    encoded_certificates.emplace_back(certificate);
  }
  return flutter::EncodableValue(encoded_certificates);
}

}  // namespace

void CertificatePinningHttpClientPlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows* registrar) {
  auto channel =
      std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
          registrar->messenger(), "certificate_pinning_httpclient",
          &flutter::StandardMethodCodec::GetInstance());

  auto plugin = std::make_unique<CertificatePinningHttpClientPlugin>();

  channel->SetMethodCallHandler(
      [plugin_pointer = plugin.get()](const auto& call, auto result) {
        plugin_pointer->HandleMethodCall(call, std::move(result));
      });

  registrar->AddPlugin(std::move(plugin));
}

CertificatePinningHttpClientPlugin::CertificatePinningHttpClientPlugin() {}

CertificatePinningHttpClientPlugin::~CertificatePinningHttpClientPlugin() {}

void CertificatePinningHttpClientPlugin::HandleMethodCall(
    const flutter::MethodCall<flutter::EncodableValue>& method_call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  if (method_call.method_name() != "fetchHostCertificates") {
    result->NotImplemented();
    return;
  }

  std::string url;
  if (!ExtractUrl(method_call.arguments(), &url)) {
    result->Error("fetchHostCertificates", "Missing or invalid URL argument");
    return;
  }

  std::thread([url, result = std::move(result)]() mutable {
    std::string error_message;
    const std::vector<std::vector<uint8_t>> certificates =
        FetchHostCertificates(url, &error_message);
    if (!error_message.empty()) {
      result->Error("fetchHostCertificates", error_message);
      return;
    }
    result->Success(ToEncodableCertificateList(certificates));
  }).detach();
}

}  // namespace certificate_pinning_httpclient
