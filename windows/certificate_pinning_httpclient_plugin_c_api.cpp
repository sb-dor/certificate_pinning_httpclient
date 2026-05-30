#include "include/certificate_pinning_httpclient/certificate_pinning_http_client_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "certificate_pinning_httpclient_plugin.h"

void CertificatePinningHttpClientPluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  certificate_pinning_httpclient::CertificatePinningHttpClientPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
