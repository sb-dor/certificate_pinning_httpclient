#ifndef FLUTTER_PLUGIN_CERTIFICATE_PINNING_HTTPCLIENT_PLUGIN_H_
#define FLUTTER_PLUGIN_CERTIFICATE_PINNING_HTTPCLIENT_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <memory>

namespace certificate_pinning_httpclient {

class CertificatePinningHttpClientPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows* registrar);

  CertificatePinningHttpClientPlugin();

  virtual ~CertificatePinningHttpClientPlugin();

  CertificatePinningHttpClientPlugin(
      const CertificatePinningHttpClientPlugin&) = delete;
  CertificatePinningHttpClientPlugin& operator=(
      const CertificatePinningHttpClientPlugin&) = delete;

  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue>& method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
};

}  // namespace certificate_pinning_httpclient

#endif  // FLUTTER_PLUGIN_CERTIFICATE_PINNING_HTTPCLIENT_PLUGIN_H_
