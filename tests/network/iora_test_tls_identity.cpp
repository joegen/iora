// TLS client SNI + certificate-identity verification (RFC 6125/9525) tests.
//
// Tracker: coding_trackers tasks/iora/ongoing/2026-09-06-2_transport-tls-sni-cert-identity_P0
// Arch doc: architecture/iora/transport_tls_sni_identity.json
//
// This target exercises C1 (the iora transport TLS-identity seam) and C2 (the
// HttpClient consumer). Deterministic in-process Catch2: a self-signed CA plus
// leaf certs with controlled SANs (dNSName / iPAddress / CN-only / wildcard /
// expired / wrong-CA) generated via the OpenSSL API, and a server whose SNI
// callback captures the observed servername.
//
// Phase-4 cases (see the tracker) are filled in as C1/C2 land:
//   task-4.2  LINCHPIN (CR-1): IP address + verifyName=domain -> SNI==domain, success
//   task-4.3  hostname mismatch -> onClose(TLSHandshake), zero onConnect
//   task-4.4  IP-literal target (verifyName empty): iPAddress-SAN match / mismatch
//   task-4.5  HTTPS hostflags: CN-only reject, partial-wildcard reject, single-label wildcard
//   task-4.6  no-peer-cert/anonymous reject; chain failures; verifyPeer=false connects + WARN
//   task-4.7  resume-path identity preservation (drive off-thread resolve)
//   task-4.12 client-role guard: server/inbound handshake NOT rejected (dual-role, mutation)
//   task-4.13 norm(): trailing-dot + mixed-case verifyName; observed SNI normalized
//   task-4.14 identity-binding fail-closed: set1_host/set1_ip failure -> connect FAILS
//   task-4.8..4.11 C2 HttpClient (e2e mismatch, caFile, mTLS, reuse, setTlsConfig, cancellable)

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "iora/core/logger.hpp"
#include "iora/network/detail/tcp_engine.hpp" // NoPeerCertEngine subclass (M-A seam)
#include "iora/network/http_client.hpp"
#include "iora/network/transport_impl.hpp"
#include "iora_test_net_utils.hpp"
#include "transport_test_seam.hpp" // TransportEngineInjector::withEngine (fault-injection)

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <fstream>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace iora::network;
using namespace std::chrono_literals;

namespace
{
using namespace std::chrono_literals;

static bool waitFor(std::function<bool()> pred, std::chrono::milliseconds timeout = 3000ms)
{
  auto deadline = std::chrono::steady_clock::now() + timeout;
  while (!pred())
  {
    if (std::chrono::steady_clock::now() > deadline) { return false; }
    std::this_thread::sleep_for(1ms);
  }
  return true;
}

// ── Small OpenSSL RAII ────────────────────────────────────────────────────────
using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&::X509_free)>;

static PkeyPtr genKey()
{
  EVP_PKEY *k = ::EVP_RSA_gen(2048); // OpenSSL 3.0 one-liner (non-deprecated)
  REQUIRE(k != nullptr);
  return PkeyPtr(k, &::EVP_PKEY_free);
}

static void addExt(X509 *cert, X509V3_CTX *ctx, int nid, const std::string &value)
{
  X509_EXTENSION *ex = ::X509V3_EXT_conf_nid(nullptr, ctx, nid, value.c_str());
  REQUIRE(ex != nullptr);
  ::X509_add_ext(cert, ex, -1);
  ::X509_EXTENSION_free(ex);
}

/// Build a certificate. \p sanEntries are OpenSSL SAN tokens, e.g. "DNS:example.com",
/// "IP:127.0.0.1", "DNS:*.example.com". notBefore/notAfter are offsets in seconds
/// from now (negative notAfter => already expired). \p issuerCert/\p issuerKey ==
/// self for a CA.
static X509Ptr makeCert(EVP_PKEY *subjectKey, X509 *issuerCert, EVP_PKEY *issuerKey,
                        const std::string &cn, const std::vector<std::string> &sanEntries,
                        bool isCa, long notBeforeSec, long notAfterSec)
{
  X509 *x = ::X509_new();
  REQUIRE(x != nullptr);
  ::X509_set_version(x, 2); // v3
  static long serial = 1000;
  ::ASN1_INTEGER_set(::X509_get_serialNumber(x), serial++);
  ::X509_gmtime_adj(::X509_getm_notBefore(x), notBeforeSec);
  ::X509_gmtime_adj(::X509_getm_notAfter(x), notAfterSec);
  ::X509_set_pubkey(x, subjectKey);

  X509_NAME *sn = ::X509_get_subject_name(x);
  ::X509_NAME_add_entry_by_txt(sn, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>(cn.c_str()), -1, -1, 0);
  ::X509_set_issuer_name(x, isCa ? sn : ::X509_get_subject_name(issuerCert));

  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx); // macro: (ctx)->db = NULL — no :: prefix
  ::X509V3_set_ctx(&ctx, isCa ? x : issuerCert, x, nullptr, nullptr, 0);
  if (isCa)
  {
    addExt(x, &ctx, NID_basic_constraints, "critical,CA:TRUE");
    addExt(x, &ctx, NID_key_usage, "critical,keyCertSign,cRLSign");
  }
  else
  {
    addExt(x, &ctx, NID_basic_constraints, "critical,CA:FALSE");
    addExt(x, &ctx, NID_key_usage, "critical,digitalSignature,keyEncipherment");
    addExt(x, &ctx, NID_ext_key_usage, "serverAuth,clientAuth");
  }
  if (!sanEntries.empty())
  {
    std::string san;
    for (std::size_t i = 0; i < sanEntries.size(); ++i)
    {
      if (i) { san += ","; }
      san += sanEntries[i];
    }
    addExt(x, &ctx, NID_subject_alt_name, san);
  }
  REQUIRE(::X509_sign(x, issuerKey, ::EVP_sha256()) > 0);
  return X509Ptr(x, &::X509_free);
}

static std::string toPemCert(X509 *x)
{
  BIO *b = ::BIO_new(::BIO_s_mem());
  ::PEM_write_bio_X509(b, x);
  char *data = nullptr;
  long n = ::BIO_get_mem_data(b, &data);
  std::string out(data, static_cast<std::size_t>(n));
  ::BIO_free(b);
  return out;
}

static std::string toPemKey(EVP_PKEY *k)
{
  BIO *b = ::BIO_new(::BIO_s_mem());
  ::PEM_write_bio_PrivateKey(b, k, nullptr, nullptr, 0, nullptr, nullptr);
  char *data = nullptr;
  long n = ::BIO_get_mem_data(b, &data);
  std::string out(data, static_cast<std::size_t>(n));
  ::BIO_free(b);
  return out;
}

// Temp PEM file that unlinks itself.
struct TempPem
{
  std::string path;
  explicit TempPem(const std::string &contents, const char *tag)
  {
    static std::atomic<int> ctr{0};
    path = "/tmp/iora_tls_" + std::to_string(::getpid()) + "_" + std::to_string(ctr++) + "_" +
           tag + ".pem";
    std::ofstream f(path, std::ios::binary);
    f << contents;
    f.close();
  }
  ~TempPem()
  {
    if (!path.empty()) { ::unlink(path.c_str()); }
  }
  TempPem(const TempPem &) = delete;
  TempPem &operator=(const TempPem &) = delete;
};

// A CA + convenience leaf builders, materialized to temp files.
struct TestPki
{
  PkeyPtr caKey;
  X509Ptr caCert;
  std::unique_ptr<TempPem> caFile;

  TestPki() : caKey(genKey()), caCert(nullptr, &::X509_free)
  {
    caCert = makeCert(caKey.get(), nullptr, caKey.get(), "iora-test-ca", {}, true,
                      -3600, 3600 * 24 * 365);
    caFile = std::make_unique<TempPem>(toPemCert(caCert.get()), "ca");
  }

  // A leaf signed by this CA. Returns (cert-file, key-file) temp paths.
  struct Leaf
  {
    PkeyPtr key;
    X509Ptr cert;
    std::unique_ptr<TempPem> certFile;
    std::unique_ptr<TempPem> keyFile;
  };

  std::shared_ptr<Leaf> leaf(const std::string &cn, const std::vector<std::string> &sans,
                             long notBeforeSec = -3600, long notAfterSec = 3600 * 24 * 365,
                             X509 *signer = nullptr, EVP_PKEY *signerKey = nullptr)
  {
    auto lf = std::make_shared<Leaf>(Leaf{genKey(), X509Ptr(nullptr, &::X509_free), nullptr, nullptr});
    lf->cert = makeCert(lf->key.get(), signer ? signer : caCert.get(),
                        signerKey ? signerKey : caKey.get(), cn, sans, false, notBeforeSec,
                        notAfterSec);
    lf->certFile = std::make_unique<TempPem>(toPemCert(lf->cert.get()), "leaf");
    lf->keyFile = std::make_unique<TempPem>(toPemKey(lf->key.get()), "key");
    return lf;
  }
};

// ── Bare-OpenSSL TLS server: accepts one connection, captures SNI, records the
// handshake outcome. The iora CLIENT is the unit under test. ────────────────────
struct BareTlsServer
{
  int listenFd{-1};
  std::uint16_t port{0};
  SSL_CTX *ctx{nullptr};
  std::thread th;
  std::atomic<bool> handshakeOk{false};
  std::atomic<bool> attempted{false};
  std::string observedSni;
  std::mutex sniMtx;

  static int sniCb(SSL *ssl, int *, void *arg)
  {
    auto *self = static_cast<BareTlsServer *>(arg);
    const char *name = ::SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    std::lock_guard<std::mutex> lk(self->sniMtx);
    self->observedSni = name ? name : "";
    return SSL_TLSEXT_ERR_OK;
  }

  bool httpRespond{false};

  // Present the leaf at \p certPath + \p keyPath. If \p httpMode, answer one HTTP
  // request with a canned 200 after the handshake. If \p clientCaPath is set,
  // require + verify a client certificate against it (mTLS).
  BareTlsServer(const std::string &certPath, const std::string &keyPath, bool httpMode = false,
                const std::string &clientCaPath = "")
    : httpRespond(httpMode)
  {
    ctx = ::SSL_CTX_new(::TLS_server_method());
    REQUIRE(ctx != nullptr);
    REQUIRE(::SSL_CTX_use_certificate_file(ctx, certPath.c_str(), SSL_FILETYPE_PEM) == 1);
    REQUIRE(::SSL_CTX_use_PrivateKey_file(ctx, keyPath.c_str(), SSL_FILETYPE_PEM) == 1);
    if (!clientCaPath.empty())
    {
      REQUIRE(::SSL_CTX_load_verify_locations(ctx, clientCaPath.c_str(), nullptr) == 1);
      ::SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    }
    ::SSL_CTX_set_tlsext_servername_callback(ctx, &BareTlsServer::sniCb);
    ::SSL_CTX_set_tlsext_servername_arg(ctx, this);

    // Dual-stack (AF_INET6 + IPV6_V6ONLY=0) so a client connecting to either
    // 127.0.0.1 (v4-mapped) or ::1 is accepted — the resume-path test drives the
    // resolver via "localhost", which may resolve v6-first (web round #4).
    listenFd = ::socket(AF_INET6, SOCK_STREAM, 0);
    REQUIRE(listenFd >= 0);
    int one = 1;
    ::setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    int v6only = 0;
    ::setsockopt(listenFd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = 0;
    REQUIRE(::bind(listenFd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
    socklen_t alen = sizeof(addr);
    REQUIRE(::getsockname(listenFd, reinterpret_cast<sockaddr *>(&addr), &alen) == 0);
    port = ::ntohs(addr.sin6_port);
    REQUIRE(::listen(listenFd, 1) == 0);
  }

  void start()
  {
    th = std::thread([this]
    {
      int cfd = ::accept(listenFd, nullptr, nullptr);
      if (cfd < 0) { return; }
      attempted = true;
      SSL *ssl = ::SSL_new(ctx);
      ::SSL_set_fd(ssl, cfd);
      int r = ::SSL_accept(ssl);
      handshakeOk = (r == 1);
      if (r == 1 && httpRespond)
      {
        char buf[4096];
        ::SSL_read(ssl, buf, sizeof(buf)); // consume the request line/headers
        static const char resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                    "Connection: close\r\n\r\nok";
        ::SSL_write(ssl, resp, static_cast<int>(sizeof(resp) - 1));
      }
      ::SSL_shutdown(ssl);
      ::SSL_free(ssl);
      ::close(cfd);
    });
  }

  ~BareTlsServer()
  {
    if (listenFd >= 0) { ::shutdown(listenFd, SHUT_RDWR); }
    if (th.joinable()) { th.join(); }
    if (listenFd >= 0) { ::close(listenFd); }
    if (ctx) { ::SSL_CTX_free(ctx); }
  }
};

// Build an iora client Transport with the given TLS client settings.
static std::shared_ptr<Transport> makeClient(const std::string &caFile, bool verifyPeer)
{
  TransportConfig cfg;
  cfg.protocol = Protocol::TCP;
  cfg.clientTls.enabled = true;
  cfg.clientTls.defaultMode = TlsMode::Client;
  cfg.clientTls.verifyPeer = verifyPeer;
  cfg.clientTls.caFile = caFile;
  auto client = Transport::tcp(std::move(cfg));
  REQUIRE(client->start().isOk());
  return client;
}

static TlsClientOptions httpsOpts(const std::string &verifyName)
{
  TlsClientOptions o;
  o.verifyName = verifyName;
  o.x509HostFlags = kHttpsHostFlags;
  return o;
}
} // namespace

// task-4.2 LINCHPIN (CR-1): connect to an IP-literal ADDRESS with verifyName set
// to a domain in the leaf's dNSName SAN -> handshake SUCCESS and the server SNI
// callback observed servername == the domain. This is the exact production shape
// the wrong (cr.host) discriminator broke.
TEST_CASE("linchpin: IP address + verifyName=domain succeeds, SNI==domain", "[tls][identity]")
{
  TestPki pki;
  auto lf = pki.leaf("example.com", {"DNS:example.com"});
  BareTlsServer server(lf->certFile->path, lf->keyFile->path);
  server.start();

  auto client = makeClient(pki.caFile->path, /*verifyPeer=*/true);
  auto r = client->connectSync("127.0.0.1", server.port, TlsMode::Client,
                               httpsOpts("example.com"), 5000ms);
  INFO("connect result: " << (r.isOk() ? "ok" : r.error().message));
  REQUIRE(r.isOk());
  REQUIRE(server.attempted.load());
  {
    std::lock_guard<std::mutex> lk(server.sniMtx);
    REQUIRE(server.observedSni == "example.com");
  }
  client->stop();
}

// task-4.3 hostname mismatch: verifyName != cert SAN -> onClose(TLSHandshake),
// ZERO onConnect (H6). Bounded wait; clean teardown.
TEST_CASE("mismatch: verifyName not in SAN -> failure, zero onConnect", "[tls][identity]")
{
  TestPki pki;
  auto lf = pki.leaf("example.com", {"DNS:example.com"});
  BareTlsServer server(lf->certFile->path, lf->keyFile->path);
  server.start();

  auto client = makeClient(pki.caFile->path, /*verifyPeer=*/true);
  std::atomic<int> onConnectCount{0};
  client->onConnect([&](SessionId, const TransportAddress &) { onConnectCount++; });

  auto r = client->connectSync("127.0.0.1", server.port, TlsMode::Client,
                               httpsOpts("wrong.example.net"), 5000ms);
  REQUIRE(r.isErr());
  REQUIRE(r.error().code == TransportError::TLSHandshake); // pin the terminal reason
  REQUIRE(onConnectCount.load() == 0); // gate fires onClose BEFORE onConnect
  client->stop();
}

namespace
{
struct ConnectOutcome
{
  bool ok{false};
  std::string sni;
  int onConnectCount{0};
};

// Spin up a bare TLS server presenting \p leaf, an iora client trusting \p pki's
// CA (unless \p caOverride is set), connect once, and report the outcome + the
// SNI the server observed. \p host is the connect address (IP literal or a name
// that drives the off-thread resolver).
static ConnectOutcome doConnect(TestPki &pki, const std::shared_ptr<TestPki::Leaf> &leaf,
                                const std::string &host, const std::string &verifyName,
                                bool verifyPeer = true, const std::string &caOverride = "")
{
  BareTlsServer server(leaf->certFile->path, leaf->keyFile->path);
  server.start();
  auto client = makeClient(caOverride.empty() ? pki.caFile->path : caOverride, verifyPeer);
  std::atomic<int> onc{0};
  client->onConnect([&](SessionId, const TransportAddress &) { onc++; });
  auto r = client->connectSync(host, server.port, TlsMode::Client, httpsOpts(verifyName), 5000ms);
  ConnectOutcome out;
  out.ok = r.isOk();
  {
    std::lock_guard<std::mutex> lk(server.sniMtx);
    out.sni = server.observedSni;
  }
  out.onConnectCount = onc.load();
  client->stop();
  return out;
}
} // namespace

// task-4.4 IP-literal target (verifyName empty): matching iPAddress-SAN -> success
// with NO SNI; non-matching IP -> failure.
TEST_CASE("ip-literal target: iPAddress-SAN match no SNI; mismatch fails", "[tls][identity]")
{
  TestPki pki;
  auto match = pki.leaf("iora-ip", {"IP:127.0.0.1"});
  auto ok = doConnect(pki, match, "127.0.0.1", /*verifyName=*/"");
  REQUIRE(ok.ok);
  REQUIRE(ok.sni.empty()); // never send an IP literal as SNI (RFC 6066 §3)

  auto wrong = pki.leaf("iora-ip", {"IP:10.9.8.7"});
  auto bad = doConnect(pki, wrong, "127.0.0.1", /*verifyName=*/"");
  REQUIRE_FALSE(bad.ok);

  // Dot-suffixed IP literal as verifyName (cpp17 R2 #1 regression-lock): the setup
  // site NORMALIZES ("127.0.0.1." -> "127.0.0.1") BEFORE the isIpLiteral check, so it
  // is recognized as an IP and routed to set1_ip_asc with NO SNI. MUTATION: normalize
  // AFTER classifying -> "127.0.0.1." fails isIpLiteral -> named branch -> SNI
  // "127.0.0.1" + set1_host, which cannot match the IP SAN -> both asserts flip red.
  auto dotted = doConnect(pki, match, "127.0.0.1", /*verifyName=*/"127.0.0.1.");
  REQUIRE(dotted.ok);
  REQUIRE(dotted.sni.empty());
}

// task-4.5 HTTPS hostflags: CN-only reject (NEVER_CHECK_SUBJECT); partial-wildcard
// reject (NO_PARTIAL_WILDCARDS); single-label wildcard matches exactly one label.
TEST_CASE("https hostflags: CN-only reject, partial-wildcard reject, single-label wildcard",
          "[tls][identity]")
{
  TestPki pki;

  // CN-only (no SAN) whose CN matches the host -> REJECTED (NEVER_CHECK_SUBJECT).
  auto cnOnly = pki.leaf("cn.example.com", {});
  REQUIRE_FALSE(doConnect(pki, cnOnly, "127.0.0.1", "cn.example.com").ok);

  // Partial-wildcard SAN -> REJECTED (NO_PARTIAL_WILDCARDS).
  auto partial = pki.leaf("partial", {"DNS:b*.example.com"});
  REQUIRE_FALSE(doConnect(pki, partial, "127.0.0.1", "bar.example.com").ok);

  // Single-label wildcard: matches one label, not zero and not two.
  auto wild = pki.leaf("wild", {"DNS:*.example.com"});
  REQUIRE(doConnect(pki, wild, "127.0.0.1", "a.example.com").ok);
  REQUIRE_FALSE(doConnect(pki, wild, "127.0.0.1", "example.com").ok);
  REQUIRE_FALSE(doConnect(pki, wild, "127.0.0.1", "a.b.example.com").ok);
}

// task-4.13 norm(): a trailing-dot + mixed-case verifyName both handshake-succeed
// against the same SAN; the observed SNI is the normalized (lowercased, no dot) form.
TEST_CASE("norm: trailing-dot + mixed-case verifyName; SNI normalized", "[tls][identity]")
{
  TestPki pki;
  auto lf = pki.leaf("example.com", {"DNS:example.com"});

  auto dot = doConnect(pki, lf, "127.0.0.1", "example.com.");
  REQUIRE(dot.ok);
  REQUIRE(dot.sni == "example.com");

  auto mixed = doConnect(pki, lf, "127.0.0.1", "EXAMPLE.CoM");
  REQUIRE(mixed.ok);
  REQUIRE(mixed.sni == "example.com");
}

// task-4.7 resume-path identity preservation (HI-1): connect to a NAME that drives
// the off-thread resolver -> verifyName reaches the setup site -> SNI observed.
TEST_CASE("resume path preserves identity: named host drives resolver", "[tls][identity]")
{
  TestPki pki;
  auto lf = pki.leaf("example.com", {"DNS:example.com"});
  // host "localhost" is a NAME (not an IP literal) so doConnect drives the
  // off-thread resolve path; verifyName must survive all 5 resume capture layers.
  auto r = doConnect(pki, lf, "localhost", "example.com");
  REQUIRE(r.ok);
  REQUIRE(r.sni == "example.com"); // vacuous unless resolution actually ran
}

// task-4.6 negative / insecure paths: chain failures reject under verifyPeer=true;
// verifyPeer=false connects (insecure) and emits the WARN.
TEST_CASE("negative paths: chain failures reject; verifyPeer=false connects + WARN",
          "[tls][identity]")
{
  TestPki pki;

  // wrong-CA: a leaf signed by a DIFFERENT CA, not in the client's trust store.
  TestPki otherCa;
  auto foreign = otherCa.leaf("example.com", {"DNS:example.com"});
  REQUIRE_FALSE(doConnect(pki, foreign, "127.0.0.1", "example.com").ok);

  // expired: notAfter in the past.
  auto expired = pki.leaf("example.com", {"DNS:example.com"}, -7200, -3600);
  REQUIRE_FALSE(doConnect(pki, expired, "127.0.0.1", "example.com").ok);

  // verifyPeer=false: connects even to a wrong-host cert (no identity), and emits
  // the insecure-mode WARN (L-c). Capture it via the logger external handler.
  std::atomic<bool> warned{false};
  iora::core::Logger::setExternalHandler(
    [&](iora::core::Logger::Level lvl, const std::string &, const std::string &raw)
    {
      if (lvl == iora::core::Logger::Level::Warning &&
          raw.find("verifyPeer=false") != std::string::npos)
      {
        warned = true;
      }
    });
  auto insecure = pki.leaf("someone.else.example", {"DNS:someone.else.example"});
  auto r = doConnect(pki, insecure, "127.0.0.1", "example.com", /*verifyPeer=*/false);
  iora::core::Logger::clearExternalHandler();
  REQUIRE(r.ok);            // insecure: connects despite the wrong host
  REQUIRE(r.sni.empty());   // verifyPeer=false => no SNI
  REQUIRE(warned.load());   // the insecure-mode WARN was emitted (L-c)
}

// task-4.14 identity-binding fail-closed (H-A): a failed OpenSSL identity call
// must FAIL the connect via the PRE-INSERTION manual terminal (never closeNow),
// with no sessionsCurrent underflow. A verifyName longer than
// TLSEXT_MAXLEN_host_name (255) makes SSL_set_tlsext_host_name return 0 — a
// deterministic, portable trigger for the fail-closed path (one of the three
// guarded calls), so this is NOT a review-only assertion.
TEST_CASE("fail-closed: over-long SNI triggers pre-insertion terminal, no gauge underflow",
          "[tls][identity]")
{
  TestPki pki;
  auto lf = pki.leaf("example.com", {"DNS:example.com"});
  BareTlsServer server(lf->certFile->path, lf->keyFile->path);
  server.start();
  auto client = makeClient(pki.caFile->path, /*verifyPeer=*/true);

  std::string tooLong(300, 'a'); // > TLSEXT_MAXLEN_host_name(255)
  tooLong += ".example.com";
  auto r = client->connectSync("127.0.0.1", server.port, TlsMode::Client, httpsOpts(tooLong),
                               5000ms);
  REQUIRE(r.isErr());
  REQUIRE(r.error().code == TransportError::TLSHandshake);

  auto stats = client->getStats();
  // sessionsPeak==0 PROVES the session was never inserted/counted -> the
  // PRE-INSERTION fail-closed terminal was taken (not a post-handshake close).
  REQUIRE(stats.sessionsPeak == 0);
  // sessionsCurrent==0: no underflow. A regression to closeNow at this pre-insertion
  // site would decrement a never-incremented gauge and wrap it to a huge value.
  REQUIRE(stats.sessionsCurrent == 0);
  REQUIRE(stats.tlsFailures >= 1); // the fail-closed terminal counts the TLS failure
  client->stop();
}

// task-4.6 (no-peer-cert / anonymous suite) — OBSERVABLE lock: a server negotiating
// an anonymous (ADH) suite presents NO certificate; the iora client MUST reject it
// (no onConnect). EMPIRICALLY (2026-09-11) the client aborts the anon handshake at
// negotiation with a TLS alert (rc!=1), so this path does NOT reach the completion
// gate's if(!pc) branch — it locks only the observable. The if(!pc) backstop itself
// (the sole rejecter when an anon cipher IS negotiated; SSL_VERIFY_PEER is ignored
// for anon per the OpenSSL contract) is exercised + mutation-locked by the separate
// fetchPeerCertificate-seam test below ("no-peer-cert backstop ... (seam)").
TEST_CASE("anonymous suite: server presents no cert -> rejected", "[tls][identity]")
{
  int lfd = ::socket(AF_INET, SOCK_STREAM, 0);
  REQUIRE(lfd >= 0);
  int one = 1;
  ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
  a.sin_port = 0;
  REQUIRE(::bind(lfd, reinterpret_cast<sockaddr *>(&a), sizeof(a)) == 0);
  socklen_t al = sizeof(a);
  REQUIRE(::getsockname(lfd, reinterpret_cast<sockaddr *>(&a), &al) == 0);
  std::uint16_t port = ::ntohs(a.sin_port);
  REQUIRE(::listen(lfd, 1) == 0);

  std::thread srv([lfd]
  {
    SSL_CTX *ctx = ::SSL_CTX_new(::TLS_server_method());
    ::SSL_CTX_set_security_level(ctx, 0);
    ::SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION); // ADH is a TLS 1.2 suite
    ::SSL_CTX_set_cipher_list(ctx, "ADH-AES256-GCM-SHA384");
    int cfd = ::accept(lfd, nullptr, nullptr);
    if (cfd >= 0)
    {
      SSL *ssl = ::SSL_new(ctx);
      ::SSL_set_fd(ssl, cfd);
      ::SSL_accept(ssl); // may complete (anon, no cert) or the client may abort
      ::SSL_shutdown(ssl);
      ::SSL_free(ssl);
      ::close(cfd);
    }
    ::SSL_CTX_free(ctx);
  });

  TransportConfig cfg;
  cfg.protocol = Protocol::TCP;
  cfg.clientTls.enabled = true;
  cfg.clientTls.defaultMode = TlsMode::Client;
  cfg.clientTls.verifyPeer = true;
  cfg.clientTls.ciphers = "ADH-AES256-GCM-SHA384:@SECLEVEL=0"; // permit anon on the client
  auto client = Transport::tcp(std::move(cfg));
  REQUIRE(client->start().isOk());
  std::atomic<int> onc{0};
  client->onConnect([&](SessionId, const TransportAddress &) { onc++; });

  auto r =
    client->connectSync("127.0.0.1", port, TlsMode::Client, httpsOpts("example.com"), 5000ms);
  // EMPIRICAL (2026-09-11): the iora client aborts the anonymous handshake at
  // negotiation with a TLS alert (rc!=1) — it does NOT complete an anon handshake
  // and reach the completion gate. So the OBSERVABLE (a cert-less/anonymous server
  // is rejected, zero onConnect) is locked here, but the completion-gate if(!pc)
  // branch is NOT the rejecter in this path (it is a genuine backstop for the case
  // where an anon cipher IS negotiated — per the OpenSSL contract SSL_VERIFY_PEER
  // is ignored for anon — which this client's cipher policy prevents black-box).
  REQUIRE(r.isErr());   // a cert-less server is never accepted
  REQUIRE(r.error().code == TransportError::TLSHandshake);
  REQUIRE(onc.load() == 0);

  client->stop();
  ::shutdown(lfd, SHUT_RDWR);
  if (srv.joinable()) { srv.join(); }
  ::close(lfd);
}

namespace
{
// Fault-injection engine (M-A seam, human sign-off 2026-09-11): pretends the peer
// presented NO certificate, so the completion-gate no-peer-cert backstop can be
// exercised on a REAL (cert-presenting) handshake. A compliant client aborts a
// genuine anonymous handshake at negotiation, so this backstop is otherwise not
// reachable black-box.
class NoPeerCertEngine : public iora::network::TcpEngine
{
public:
  using iora::network::TcpEngine::TcpEngine;

protected:
  X509 *fetchPeerCertificate(SSL *) override { return nullptr; }
};
} // namespace

// task-4.6 (no-peer-cert backstop, via the fetchPeerCertificate seam): with a VALID,
// matching server cert the handshake SUCCEEDS (rc==1), but the seam forces the peer
// cert to null, so the completion gate's if(!pc) backstop MUST reject with
// "no peer certificate". MUTATION: remove the if(!pc) block -> the real valid cert
// gives X509_V_OK -> onConnect fires -> this test flips red, locking the backstop.
TEST_CASE("no-peer-cert backstop: completion gate rejects a cert-less rc==1 (seam)",
          "[tls][identity]")
{
  TestPki pki;
  auto lf = pki.leaf("example.com", {"DNS:example.com"});
  BareTlsServer server(lf->certFile->path, lf->keyFile->path); // presents a VALID cert
  server.start();

  TransportConfig cfg;
  cfg.protocol = Protocol::TCP;
  cfg.clientTls.enabled = true;
  cfg.clientTls.defaultMode = TlsMode::Client;
  cfg.clientTls.verifyPeer = true;
  cfg.clientTls.caFile = pki.caFile->path;
  auto engine = std::make_unique<NoPeerCertEngine>(cfg);
  auto client = iora::network::test::TransportEngineInjector::withEngine(std::move(engine), cfg);
  REQUIRE(client->start().isOk());
  std::atomic<int> onc{0};
  client->onConnect([&](SessionId, const TransportAddress &) { onc++; });

  auto r =
    client->connectSync("127.0.0.1", server.port, TlsMode::Client, httpsOpts("example.com"), 5000ms);
  REQUIRE(r.isErr());
  REQUIRE(r.error().code == TransportError::TLSHandshake);
  REQUIRE(r.error().message.find("no peer certificate") != std::string::npos);
  REQUIRE(onc.load() == 0);
  client->stop();
}

// task-4.12 client-role guard (R2-H1): an INBOUND/server-accepted TLS handshake on
// a DUAL-ROLE iora engine (clientTls.enabled && verifyPeer both true) must NOT be
// rejected by the client-role-guarded completion gate. The bare client presents NO
// client certificate; without the tlsMode==Client guard the gate would demand a
// peer cert on the server session and reject it — so a passing accept here is the
// regression lock for the guard.
TEST_CASE("client-role guard: dual-role server accepts inbound TLS", "[tls][identity]")
{
  TestPki pki;
  auto lf = pki.leaf("iora-server", {"DNS:iora-server", "IP:127.0.0.1"});

  auto port = testnet::getFreePortTCP();
  TransportConfig serverCfg;
  serverCfg.protocol = Protocol::TCP;
  serverCfg.serverTls.enabled = true;
  serverCfg.serverTls.defaultMode = TlsMode::Server;
  serverCfg.serverTls.certFile = lf->certFile->path;
  serverCfg.serverTls.keyFile = lf->keyFile->path;
  // DUAL-ROLE: client TLS also enabled + verifyPeer true (the proxy/SBC shape).
  // The completion gate must skip these knobs for a server-accepted session.
  serverCfg.clientTls.enabled = true;
  serverCfg.clientTls.defaultMode = TlsMode::Client;
  serverCfg.clientTls.verifyPeer = true;
  serverCfg.clientTls.caFile = pki.caFile->path;
  auto server = Transport::tcp(std::move(serverCfg));

  std::atomic<int> acceptCount{0};
  std::atomic<int> serverClose{0};
  server->onAccept([&](SessionId, const TransportAddress &) { acceptCount++; });
  server->onClose([&](SessionId, const TransportErrorInfo &) { serverClose++; });
  REQUIRE(server->start().isOk());
  REQUIRE(server->addListener("127.0.0.1", port, TlsMode::Server).isOk());

  // Bare-OpenSSL client presenting NO client cert.
  SSL_CTX *cctx = ::SSL_CTX_new(::TLS_client_method());
  REQUIRE(cctx != nullptr);
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  REQUIRE(fd >= 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
  addr.sin_port = ::htons(port);
  REQUIRE(::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
  SSL *ssl = ::SSL_new(cctx);
  ::SSL_set_fd(ssl, fd);
  int hs = ::SSL_connect(ssl);

  REQUIRE(hs == 1);                        // the inbound handshake COMPLETED
  REQUIRE(waitFor([&] { return acceptCount.load() > 0; }, 3000ms));
  REQUIRE(serverClose.load() == 0);        // server did NOT reject the cert-less client

  ::SSL_shutdown(ssl);
  ::SSL_free(ssl);
  ::close(fd);
  ::SSL_CTX_free(cctx);
  server->stop();
}

namespace
{
static std::string httpsUrl(std::uint16_t port, const std::string &host = "localhost")
{
  return "https://" + host + ":" + std::to_string(port) + "/";
}

// Keep-alive HTTPS server that counts DISTINCT accepted connections and answers
// each request without "Connection: close" so the client can pool + reuse the
// socket. Used to prove distinct cache keys open distinct connections (HI-7).
struct KeepAliveHttpsServer
{
  int listenFd{-1};
  std::uint16_t port{0};
  SSL_CTX *ctx{nullptr};
  std::thread acceptTh;
  std::vector<std::thread> connThreads;
  std::mutex connMtx;
  std::atomic<bool> stop{false};
  std::atomic<int> connections{0};

  KeepAliveHttpsServer(const std::string &certPath, const std::string &keyPath)
  {
    ctx = ::SSL_CTX_new(::TLS_server_method());
    REQUIRE(ctx != nullptr);
    REQUIRE(::SSL_CTX_use_certificate_file(ctx, certPath.c_str(), SSL_FILETYPE_PEM) == 1);
    REQUIRE(::SSL_CTX_use_PrivateKey_file(ctx, keyPath.c_str(), SSL_FILETYPE_PEM) == 1);
    listenFd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(listenFd >= 0);
    int one = 1;
    ::setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    REQUIRE(::bind(listenFd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
    socklen_t alen = sizeof(addr);
    REQUIRE(::getsockname(listenFd, reinterpret_cast<sockaddr *>(&addr), &alen) == 0);
    port = ::ntohs(addr.sin_port);
    REQUIRE(::listen(listenFd, 8) == 0);
  }

  void start()
  {
    acceptTh = std::thread([this]
    {
      while (!stop.load())
      {
        int cfd = ::accept(listenFd, nullptr, nullptr);
        if (cfd < 0) { break; }
        connections++;
        std::lock_guard<std::mutex> lk(connMtx);
        connThreads.emplace_back([this, cfd]
        {
          SSL *ssl = ::SSL_new(ctx);
          ::SSL_set_fd(ssl, cfd);
          if (::SSL_accept(ssl) == 1)
          {
            char buf[4096];
            while (true)
            {
              int n = ::SSL_read(ssl, buf, sizeof(buf));
              if (n <= 0) { break; } // peer closed / error
              static const char resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
              ::SSL_write(ssl, resp, static_cast<int>(sizeof(resp) - 1));
            }
          }
          ::SSL_shutdown(ssl);
          ::SSL_free(ssl);
          ::close(cfd);
        });
      }
    });
  }

  ~KeepAliveHttpsServer()
  {
    stop = true;
    if (listenFd >= 0) { ::shutdown(listenFd, SHUT_RDWR); }
    if (acceptTh.joinable()) { acceptTh.join(); }
    std::lock_guard<std::mutex> lk(connMtx);
    for (auto &t : connThreads)
    {
      if (t.joinable()) { t.join(); }
    }
    if (listenFd >= 0) { ::close(listenFd); }
    if (ctx) { ::SSL_CTX_free(ctx); }
  }
};
} // namespace

// task-4.9 connection reuse / cache key (HI-7): the cache key uses the ORIGINAL
// host, not the resolved IP. Two requests to the SAME host string reuse ONE pooled
// connection; a request to a DIFFERENT host string (same resolved IP:port) opens a
// SECOND connection. (The scheme-qualified original-host key is also independently
// locked by iora_test_http_client_scheme_cache_key; task-3.4 changed no code.)
TEST_CASE("httpclient reuse: same host reuses, distinct host opens a new connection",
          "[tls][http]")
{
  TestPki pki;
  // Cert valid for BOTH the DNS name and the IP literal so both host strings pass
  // identity — isolating the cache-key behavior from identity verification.
  auto lf = pki.leaf("localhost", {"DNS:localhost", "IP:127.0.0.1"});
  KeepAliveHttpsServer server(lf->certFile->path, lf->keyFile->path);
  server.start();

  HttpClient client;
  HttpClient::TlsConfig tc;
  tc.caFile = pki.caFile->path;
  tc.verifyPeer = true;
  client.setTlsConfig(tc);

  REQUIRE(client.get(httpsUrl(server.port, "localhost")).statusCode == 200);
  REQUIRE(client.get(httpsUrl(server.port, "localhost")).statusCode == 200);
  REQUIRE(server.connections.load() == 1); // same key => pooled connection reused

  REQUIRE(client.get(httpsUrl(server.port, "127.0.0.1")).statusCode == 200);
  REQUIRE(server.connections.load() == 2); // distinct host string => distinct key => new conn
}

// task-4.8 C2 HttpClient: HTTPS e2e mismatch (MITM regression-lock, ME-6) + caFile
// (H5) + mTLS (H5). HttpClient requests https://localhost:port (a NAME -> verifyName
// "localhost"), so cert identity is genuinely checked.
TEST_CASE("httpclient https: e2e mismatch fails, caFile success/failure, mTLS", "[tls][http]")
{
  SECTION("caFile success against a private-CA chain")
  {
    TestPki pki;
    auto lf = pki.leaf("localhost", {"DNS:localhost"});
    BareTlsServer server(lf->certFile->path, lf->keyFile->path, /*httpMode=*/true);
    server.start();
    HttpClient client;
    HttpClient::TlsConfig tc;
    tc.caFile = pki.caFile->path;
    tc.verifyPeer = true;
    client.setTlsConfig(tc);
    auto resp = client.get(httpsUrl(server.port));
    REQUIRE(resp.statusCode == 200);
  }

  SECTION("e2e mismatch: cert valid for a DIFFERENT name -> request FAILS")
  {
    TestPki pki;
    auto lf = pki.leaf("notlocalhost", {"DNS:notlocalhost"});
    BareTlsServer server(lf->certFile->path, lf->keyFile->path, /*httpMode=*/true);
    server.start();
    HttpClient client;
    HttpClient::TlsConfig tc;
    tc.caFile = pki.caFile->path;
    tc.verifyPeer = true;
    client.setTlsConfig(tc);
    REQUIRE_THROWS(client.get(httpsUrl(server.port)));
  }

  SECTION("caFile unset: private-CA chain not trusted -> request FAILS")
  {
    TestPki pki;
    auto lf = pki.leaf("localhost", {"DNS:localhost"});
    BareTlsServer server(lf->certFile->path, lf->keyFile->path, /*httpMode=*/true);
    server.start();
    HttpClient client; // default verifyPeer=true, no caFile => system trust store only
    REQUIRE_THROWS(client.get(httpsUrl(server.port)));
  }

  SECTION("mTLS: client cert presented and accepted")
  {
    TestPki pki;
    auto serverLeaf = pki.leaf("localhost", {"DNS:localhost"});
    auto clientLeaf = pki.leaf("iora-http-client", {"DNS:iora-http-client"});
    BareTlsServer server(serverLeaf->certFile->path, serverLeaf->keyFile->path,
                         /*httpMode=*/true, /*clientCaPath=*/pki.caFile->path);
    server.start();
    HttpClient client;
    HttpClient::TlsConfig tc;
    tc.caFile = pki.caFile->path;
    tc.clientCertFile = clientLeaf->certFile->path;
    tc.clientKeyFile = clientLeaf->keyFile->path;
    tc.verifyPeer = true;
    client.setTlsConfig(tc);
    auto resp = client.get(httpsUrl(server.port));
    REQUIRE(resp.statusCode == 200);
  }
}

// task-4.10 C2 setTlsConfig contract (HI-6): a before-first-request setTlsConfig is
// in force on the first connection; an after-first-request setTlsConfig THROWS (not
// a silent no-op).
TEST_CASE("httpclient setTlsConfig: before-request in force; after-request throws", "[tls][http]")
{
  TestPki pki;
  auto lf = pki.leaf("localhost", {"DNS:localhost"});
  BareTlsServer server(lf->certFile->path, lf->keyFile->path, /*httpMode=*/true);
  server.start();

  HttpClient client;
  HttpClient::TlsConfig tc;
  tc.caFile = pki.caFile->path; // private CA: the request succeeds ONLY if applied
  tc.verifyPeer = true;
  client.setTlsConfig(tc); // before first request: accepted + in force
  auto resp = client.get(httpsUrl(server.port));
  REQUIRE(resp.statusCode == 200); // proves the caFile was applied on the first connection

  // After the transport is initialized: fail loud, never a silent no-op.
  REQUIRE_THROWS_AS(client.setTlsConfig(tc), std::logic_error);
}

// task-4.11 C2 connectSyncCancellable TLS (R2-H3): a TLS connect via
// connectSyncCancellable carries verifyName and enforces identity (NOT fail-open) —
// a mismatch fails; a match succeeds.
TEST_CASE("connectSyncCancellable carries identity: mismatch fails, match succeeds", "[tls][http]")
{
  TestPki pki;
  auto lf = pki.leaf("example.com", {"DNS:example.com"});

  {
    BareTlsServer server(lf->certFile->path, lf->keyFile->path);
    server.start();
    auto client = makeClient(pki.caFile->path, /*verifyPeer=*/true);
    CancellationToken token;
    auto bad = client->connectSyncCancellable("127.0.0.1", server.port, token, TlsMode::Client,
                                              5000ms, httpsOpts("wrong.example.net"));
    REQUIRE(bad.isErr()); // identity enforced, not a silent fail-open
    REQUIRE(bad.error().code == TransportError::TLSHandshake); // pin the terminal reason
    client->stop();
  }
  {
    BareTlsServer server(lf->certFile->path, lf->keyFile->path);
    server.start();
    auto client = makeClient(pki.caFile->path, /*verifyPeer=*/true);
    CancellationToken token;
    auto ok = client->connectSyncCancellable("127.0.0.1", server.port, token, TlsMode::Client,
                                             5000ms, httpsOpts("example.com"));
    REQUIRE(ok.isOk());
    client->stop();
  }
}
