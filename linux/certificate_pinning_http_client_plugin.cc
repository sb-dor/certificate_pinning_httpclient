#include "include/certificate_pinning_httpclient/certificate_pinning_http_client_plugin.h"

#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cctype>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#define CERTIFICATE_PINNING_HTTP_CLIENT_PLUGIN(obj)                         \
  (G_TYPE_CHECK_INSTANCE_CAST((obj),                                        \
                              certificate_pinning_http_client_plugin_get_type(), \
                              CertificatePinningHttpClientPlugin))

struct _CertificatePinningHttpClientPlugin {
  GObject parent_instance;
};

G_DEFINE_TYPE(CertificatePinningHttpClientPlugin,
              certificate_pinning_http_client_plugin,
              g_object_get_type())

namespace {

struct FetchRequest {
  gchar* url;
};

struct FetchResult {
  std::vector<std::vector<uint8_t>> certificates;
  std::string error;
};

struct ParsedUrl {
  std::string host;
  int port = 443;
};

void fetch_request_free(FetchRequest* request) {
  if (!request) {
    return;
  }
  g_free(request->url);
  delete request;
}

std::string openssl_error(const char* prefix) {
  const unsigned long error = ERR_get_error();
  if (error == 0) {
    return prefix;
  }

  char buffer[256] = {};
  ERR_error_string_n(error, buffer, sizeof(buffer));
  return std::string(prefix) + ": " + buffer;
}

bool starts_with_https_scheme(const std::string& url) {
  constexpr char scheme[] = "https://";
  if (url.size() < strlen(scheme)) {
    return false;
  }

  for (size_t i = 0; i < strlen(scheme); i++) {
    if (std::tolower(static_cast<unsigned char>(url[i])) != scheme[i]) {
      return false;
    }
  }
  return true;
}

bool parse_https_url(const gchar* url, ParsedUrl* parsed, std::string* error) {
  const std::string value = url ? url : "";
  if (!starts_with_https_scheme(value)) {
    *error = "Only HTTPS URLs are supported";
    return false;
  }

  const size_t authority_start = strlen("https://");
  const size_t authority_end = value.find_first_of("/?#", authority_start);
  const std::string authority = value.substr(
      authority_start,
      authority_end == std::string::npos ? std::string::npos
                                         : authority_end - authority_start);
  if (authority.empty()) {
    *error = "Missing URL host";
    return false;
  }

  if (authority.front() == '[') {
    const size_t closing_bracket = authority.find(']');
    if (closing_bracket == std::string::npos) {
      *error = "Invalid IPv6 host";
      return false;
    }
    parsed->host = authority.substr(1, closing_bracket - 1);
    if (closing_bracket + 1 < authority.size()) {
      if (authority[closing_bracket + 1] != ':') {
        *error = "Invalid URL authority";
        return false;
      }
      try {
        parsed->port = std::stoi(authority.substr(closing_bracket + 2));
      } catch (...) {
        *error = "Invalid URL port";
        return false;
      }
    }
    return true;
  }

  const size_t port_separator = authority.rfind(':');
  if (port_separator == std::string::npos) {
    parsed->host = authority;
    return true;
  }

  parsed->host = authority.substr(0, port_separator);
  if (parsed->host.empty()) {
    *error = "Missing URL host";
    return false;
  }
  try {
    parsed->port = std::stoi(authority.substr(port_separator + 1));
  } catch (...) {
    *error = "Invalid URL port";
    return false;
  }
  return true;
}

bool add_certificate_der(X509* certificate,
                         std::vector<std::vector<uint8_t>>* certificates,
                         std::string* error) {
  const int der_length = i2d_X509(certificate, nullptr);
  if (der_length <= 0) {
    *error = openssl_error("i2d_X509 length failed");
    return false;
  }

  std::vector<uint8_t> der(static_cast<size_t>(der_length));
  unsigned char* cursor = der.data();
  if (i2d_X509(certificate, &cursor) <= 0) {
    *error = openssl_error("i2d_X509 failed");
    return false;
  }

  certificates->push_back(std::move(der));
  return true;
}

FetchResult fetch_host_certificates(const gchar* url) {
  FetchResult result;

  ParsedUrl parsed_url;
  if (!parse_https_url(url, &parsed_url, &result.error)) {
    return result;
  }

  SSL_CTX* raw_context = SSL_CTX_new(TLS_client_method());
  if (!raw_context) {
    result.error = openssl_error("SSL_CTX_new failed");
    return result;
  }
  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(raw_context,
                                                            SSL_CTX_free);

  SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER, nullptr);
  if (SSL_CTX_set_default_verify_paths(context.get()) != 1) {
    result.error = openssl_error("SSL_CTX_set_default_verify_paths failed");
    return result;
  }

  BIO* raw_bio = BIO_new_ssl_connect(context.get());
  if (!raw_bio) {
    result.error = openssl_error("BIO_new_ssl_connect failed");
    return result;
  }
  std::unique_ptr<BIO, decltype(&BIO_free_all)> bio(raw_bio, BIO_free_all);

  SSL* ssl = nullptr;
  BIO_get_ssl(bio.get(), &ssl);
  if (!ssl) {
    result.error = "BIO_get_ssl failed";
    return result;
  }

  SSL_set_tlsext_host_name(ssl, parsed_url.host.c_str());
  SSL_set1_host(ssl, parsed_url.host.c_str());

  BIO_set_conn_hostname(
      bio.get(),
      (parsed_url.host + ":" + std::to_string(parsed_url.port)).c_str());

  if (BIO_do_connect(bio.get()) != 1) {
    result.error = openssl_error("BIO_do_connect failed");
    return result;
  }

  if (BIO_do_handshake(bio.get()) != 1) {
    result.error = openssl_error("BIO_do_handshake failed");
    return result;
  }

  if (SSL_get_verify_result(ssl) != X509_V_OK) {
    result.error = X509_verify_cert_error_string(SSL_get_verify_result(ssl));
    return result;
  }

  X509* leaf_certificate = SSL_get_peer_certificate(ssl);
  if (!leaf_certificate) {
    result.error = "Server did not provide a certificate";
    return result;
  }
  std::unique_ptr<X509, decltype(&X509_free)> leaf_certificate_owner(
      leaf_certificate, X509_free);

  if (!add_certificate_der(leaf_certificate, &result.certificates,
                           &result.error)) {
    return result;
  }

  STACK_OF(X509)* chain = SSL_get_peer_cert_chain(ssl);
  if (chain) {
    const int count = sk_X509_num(chain);
    for (int index = 0; index < count; index++) {
      X509* certificate = sk_X509_value(chain, index);
      if (certificate == leaf_certificate) {
        continue;
      }
      if (!add_certificate_der(certificate, &result.certificates,
                               &result.error)) {
        return result;
      }
    }
  }

  return result;
}

FlMethodResponse* fetch_result_to_response(FetchResult* fetch_result) {
  if (!fetch_result->error.empty()) {
    return FL_METHOD_RESPONSE(fl_method_error_response_new(
        "fetchHostCertificates", fetch_result->error.c_str(), nullptr));
  }

  g_autoptr(FlValue) certificates = fl_value_new_list();
  for (const auto& certificate : fetch_result->certificates) {
    fl_value_append_take(
        certificates,
        fl_value_new_uint8_list(certificate.data(), certificate.size()));
  }

  return FL_METHOD_RESPONSE(fl_method_success_response_new(certificates));
}

void fetch_host_certificates_task(GTask* task,
                                  gpointer source_object,
                                  gpointer task_data,
                                  GCancellable* cancellable) {
  FetchRequest* request = static_cast<FetchRequest*>(task_data);
  FetchResult* result = new FetchResult(fetch_host_certificates(request->url));
  g_task_return_pointer(task, result, [](gpointer data) {
    delete static_cast<FetchResult*>(data);
  });
}

void fetch_host_certificates_done(GObject* source_object,
                                  GAsyncResult* async_result,
                                  gpointer user_data) {
  FlMethodCall* method_call = FL_METHOD_CALL(source_object);
  g_autoptr(GError) error = nullptr;
  FetchResult* fetch_result = static_cast<FetchResult*>(
      g_task_propagate_pointer(G_TASK(async_result), &error));

  g_autoptr(FlMethodResponse) response = nullptr;
  if (error) {
    response = FL_METHOD_RESPONSE(fl_method_error_response_new(
        "fetchHostCertificates", error->message, nullptr));
  } else if (!fetch_result) {
    response = FL_METHOD_RESPONSE(fl_method_error_response_new(
        "fetchHostCertificates", "Certificate fetch failed", nullptr));
  } else {
    response = fetch_result_to_response(fetch_result);
  }
  delete fetch_result;

  fl_method_call_respond(method_call, response, nullptr);
}

void handle_method_call(CertificatePinningHttpClientPlugin* self,
                        FlMethodCall* method_call) {
  const gchar* method = fl_method_call_get_name(method_call);

  if (strcmp(method, "fetchHostCertificates") != 0) {
    g_autoptr(FlMethodResponse) response =
        FL_METHOD_RESPONSE(fl_method_not_implemented_response_new());
    fl_method_call_respond(method_call, response, nullptr);
    return;
  }

  FlValue* args = fl_method_call_get_args(method_call);
  FlValue* url_value = args ? fl_value_lookup_string(args, "url") : nullptr;
  if (!url_value || fl_value_get_type(url_value) != FL_VALUE_TYPE_STRING) {
    g_autoptr(FlMethodResponse) response =
        FL_METHOD_RESPONSE(fl_method_error_response_new(
            "fetchHostCertificates", "Missing or invalid URL argument",
            nullptr));
    fl_method_call_respond(method_call, response, nullptr);
    return;
  }

  FetchRequest* request = new FetchRequest{
      g_strdup(fl_value_get_string(url_value)),
  };
  g_autoptr(GTask) task =
      g_task_new(G_OBJECT(method_call), nullptr, fetch_host_certificates_done,
                 nullptr);
  g_task_set_task_data(task, request,
                       reinterpret_cast<GDestroyNotify>(fetch_request_free));
  g_task_run_in_thread(task, fetch_host_certificates_task);
}

}  // namespace

static void certificate_pinning_http_client_plugin_dispose(GObject* object) {
  G_OBJECT_CLASS(certificate_pinning_http_client_plugin_parent_class)
      ->dispose(object);
}

static void certificate_pinning_http_client_plugin_class_init(
    CertificatePinningHttpClientPluginClass* klass) {
  G_OBJECT_CLASS(klass)->dispose =
      certificate_pinning_http_client_plugin_dispose;
}

static void certificate_pinning_http_client_plugin_init(
    CertificatePinningHttpClientPlugin* self) {}

static void method_call_cb(FlMethodChannel* channel,
                           FlMethodCall* method_call,
                           gpointer user_data) {
  CertificatePinningHttpClientPlugin* plugin =
      CERTIFICATE_PINNING_HTTP_CLIENT_PLUGIN(user_data);
  handle_method_call(plugin, method_call);
}

void certificate_pinning_http_client_plugin_register_with_registrar(
    FlPluginRegistrar* registrar) {
  CertificatePinningHttpClientPlugin* plugin =
      CERTIFICATE_PINNING_HTTP_CLIENT_PLUGIN(g_object_new(
          certificate_pinning_http_client_plugin_get_type(), nullptr));

  g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();
  g_autoptr(FlMethodChannel) channel = fl_method_channel_new(
      fl_plugin_registrar_get_messenger(registrar),
      "certificate_pinning_httpclient", FL_METHOD_CODEC(codec));
  fl_method_channel_set_method_call_handler(channel, method_call_cb,
                                            g_object_ref(plugin),
                                            g_object_unref);

  g_object_unref(plugin);
}
