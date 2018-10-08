/**
 * @file ConnectionTests.cpp
 *
 * This module contains the unit tests of the
 * TwitchNetworkTransport::Connection class.
 *
 * © 2018 by Richard Walters
 */

#include <condition_variable>
#include <gtest/gtest.h>
#include <TwitchNetworkTransport/Connection.hpp>
#include <inttypes.h>
#include <mutex>
#include <stdint.h>
#include <SystemAbstractions/NetworkEndpoint.hpp>
#include <SystemAbstractions/StringExtensions.hpp>
#include <TlsDecorator/TlsShim.hpp>
#include <thread>
#include <vector>

namespace {

    /**
     * This is an alternative TlsShim which mocks the libtls
     * library completely.
     */
    struct MockTls
        : public TlsDecorator::TlsShim
    {
        // Properties

        bool tlsServerMode = false;
        bool tlsConnectCalled = false;
        bool tlsHandshakeCalled = false;
        bool tlsAcceptCalled = false;
        bool tlsConfigProtocolSetCalled = false;
        uint32_t tlsConfigProtocolSetProtocols = 0;
        bool tlsConfigureCalled = false;
        std::string peerCert;
        std::string caCerts;
        std::string configuredCert;
        std::string configuredKey;
        std::string encryptedKey;
        std::string keyPassword;
        std::string decryptedKey;
        bool tlsReadCalled = false;
        bool tlsWriteCalled = false;
        bool stallTlsWrite = false;
        tls_read_cb tlsReadCb = NULL;
        tls_write_cb tlsWriteCb = NULL;
        void* tlsCbArg = NULL;
        std::vector< uint8_t > tlsWriteDecryptedBuf;
        std::vector< uint8_t > tlsWriteEncryptedBuf;
        std::vector< uint8_t > tlsReadEncryptedBuf;
        std::vector< uint8_t > tlsReadDecryptedBuf;
        std::condition_variable wakeCondition;
        std::mutex mutex;

        // Methods

        /**
         * This method waits on the mock's wait condition until
         * the given predicate evaluates to true.
         *
         * @note
         *     Ensure that the predicate used is associated with
         *     the mock's wait condition.  Otherwise, the method
         *     may wait the full timeout period unnecessarily.
         *
         * @param[in] predicate
         *     This is the function to call to determine whether
         *     or not the condition we're waiting for is true.
         *
         * @param[in] timeout
         *     This is the maximum amount of time to wait.
         *
         * @return
         *     An indication of whether or not the given condition
         *     became true before a reasonable timeout period is returned.
         */
        bool Await(
            std::function< bool() > predicate,
            std::chrono::milliseconds timeout = std::chrono::milliseconds(1000)
        ) {
            std::unique_lock< decltype(mutex) > lock(mutex);
            return wakeCondition.wait_for(
                lock,
                timeout,
                predicate
            );
        }

        // TlsDecorator::TlsShim

        virtual BIO *BIO_new(const BIO_METHOD *type) override {
            return nullptr;
        }

        virtual BIO *BIO_new_mem_buf(const void *buf, int len) override {
            encryptedKey = std::string(
                (const char*)buf,
                len
            );
            return nullptr;
        }

        virtual long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg) override {
            *((const char**)parg) = decryptedKey.c_str();
            return (long)decryptedKey.size();
        }

        virtual void BIO_free_all(BIO *a) override {
        }

        virtual EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u) override {
            static EVP_PKEY dummy;
            keyPassword = (const char*)u;
            return &dummy;
        }

        virtual int PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
            unsigned char *kstr, int klen, pem_password_cb *cb, void *u) override
        {
            return 1;
        }

        virtual void EVP_PKEY_free(EVP_PKEY *pkey) override {
        }

        virtual const char *tls_error(struct tls *_ctx) override {
            return nullptr;
        }

        virtual struct tls_config *tls_config_new(void) override {
            return nullptr;
        }

        virtual int tls_config_set_protocols(struct tls_config *_config, uint32_t _protocols) override {
            tlsConfigProtocolSetCalled = true;
            tlsConfigProtocolSetProtocols = _protocols;
            return 0;
        }

        virtual void tls_config_insecure_noverifycert(struct tls_config *_config) override {
        }

        virtual void tls_config_insecure_noverifyname(struct tls_config *_config) override {
        }

        virtual int tls_config_set_ca_mem(struct tls_config *_config, const uint8_t *_ca,
            size_t _len) override
        {
            caCerts = std::string(
                (const char*)_ca,
                _len
            );
            return 0;
        }

        virtual int tls_config_set_cert_mem(struct tls_config *_config, const uint8_t *_cert,
            size_t _len) override
        {
            configuredCert = std::string(
                (const char*)_cert,
                _len
            );
            return 0;
        }

        virtual int tls_config_set_key_mem(struct tls_config *_config, const uint8_t *_key,
            size_t _len) override
        {
            configuredKey = std::string(
                (const char*)_key,
                _len
            );
            return 0;
        }

        virtual int tls_configure(struct tls *_ctx, struct tls_config *_config) override {
            tlsConfigureCalled = true;
            return 0;
        }

        virtual void tls_config_free(struct tls_config *_config) override {
        }

        virtual struct tls *tls_client(void) override {
            tlsServerMode = false;
            return nullptr;
        }

        virtual struct tls *tls_server(void) override {
            tlsServerMode = true;
            return nullptr;
        }

        virtual int tls_connect_cbs(struct tls *_ctx, tls_read_cb _read_cb,
            tls_write_cb _write_cb, void *_cb_arg, const char *_servername) override
        {
            tlsConnectCalled = true;
            tlsReadCb = _read_cb;
            tlsWriteCb = _write_cb;
            tlsCbArg = _cb_arg;
            return 0;
        }

        virtual int tls_accept_cbs(struct tls *_ctx, struct tls **_cctx,
            tls_read_cb _read_cb, tls_write_cb _write_cb, void *_cb_arg) override
        {
            tlsAcceptCalled = true;
            tlsReadCb = _read_cb;
            tlsWriteCb = _write_cb;
            tlsCbArg = _cb_arg;
            return 0;
        }

        virtual int tls_handshake(struct tls *_ctx) override {
            std::lock_guard< decltype(mutex) > lock(mutex);
            tlsHandshakeCalled = true;
            wakeCondition.notify_all();
            return 0;
        }

        virtual int tls_peer_cert_provided(struct tls *_ctx) override {
            return 1;
        }

        virtual const uint8_t *tls_peer_cert_chain_pem(struct tls *_ctx, size_t *_len) override {
            *_len = peerCert.length();
            return (const uint8_t*)peerCert.data();
        }

        virtual ssize_t tls_read(struct tls *_ctx, void *_buf, size_t _buflen) override {
            tlsReadCalled = true;
            if (tlsReadEncryptedBuf.empty()) {
                tlsReadEncryptedBuf.resize(65536);
                const auto encryptedAmount = tlsReadCb(_ctx, tlsReadEncryptedBuf.data(), tlsReadEncryptedBuf.size(), tlsCbArg);
                std::lock_guard< decltype(mutex) > lock(mutex);
                if (encryptedAmount >= 0) {
                    tlsReadEncryptedBuf.resize((size_t)encryptedAmount);
                } else {
                    tlsReadEncryptedBuf.clear();
                }
                wakeCondition.notify_all();
            }
            const auto decryptedAmount = std::min(tlsReadDecryptedBuf.size(), _buflen);
            if (decryptedAmount == 0) {
                return TLS_WANT_POLLIN;
            } else {
                (void)memcpy(_buf, tlsReadDecryptedBuf.data(), decryptedAmount);
                if (decryptedAmount == tlsReadDecryptedBuf.size()) {
                    tlsReadDecryptedBuf.clear();
                } else {
                    (void)tlsReadDecryptedBuf.erase(
                        tlsReadDecryptedBuf.begin(),
                        tlsReadDecryptedBuf.begin() + decryptedAmount
                    );
                }
                return decryptedAmount;
            }
        }

        virtual ssize_t tls_write(struct tls *_ctx, const void *_buf, size_t _buflen) override {
            std::lock_guard< decltype(mutex) > lock(mutex);
            tlsWriteCalled = true;
            if (stallTlsWrite) {
                return TLS_WANT_POLLIN;
            }
            const auto bufAsBytes = (const uint8_t*)_buf;
            tlsWriteDecryptedBuf.assign(bufAsBytes, bufAsBytes + _buflen);
            const auto encryptedAmount = tlsWriteCb(_ctx, tlsWriteEncryptedBuf.data(), tlsWriteEncryptedBuf.size(), tlsCbArg);
            if (encryptedAmount == tlsWriteEncryptedBuf.size()) {
                tlsWriteEncryptedBuf.clear();
            } else {
                (void)tlsWriteEncryptedBuf.erase(
                    tlsWriteEncryptedBuf.begin(),
                    tlsWriteEncryptedBuf.begin() + encryptedAmount
                );
            }
            wakeCondition.notify_all();
            return _buflen;
        }

        virtual int tls_close(struct tls *_ctx) override {
            return 0;
        }

        virtual void tls_free(struct tls *_ctx) override {
        }
    };

    /**
     * This holds information about one client that is connected
     * to the server used in the text fixture for these tests.
     */
    struct Client {
        /**
         * This is the server end of the connection between the unit under
         * test and the server.
         */
        std::shared_ptr< SystemAbstractions::NetworkConnection > connection;

        /**
         * This holds any data received from the client.
         */
        std::vector< uint8_t > dataReceived;

        /**
         * This flag indicates whether or not the connection to the client
         * was broken by the client.
         */
        bool broken = false;
    };

    /**
     * This is a substitute for a real connection, and used to test
     * the SetConnectionFactory method of Connection.
     */
    struct MockConnection
        : public SystemAbstractions::INetworkConnection
    {
        // Properties

        std::vector< uint8_t > messageSent;

        // Methods

        // SystemAbstractions::INetworkConnection

        virtual SystemAbstractions::DiagnosticsSender::UnsubscribeDelegate SubscribeToDiagnostics(
            SystemAbstractions::DiagnosticsSender::DiagnosticMessageDelegate delegate,
            size_t minLevel = 0
        ) override {
            return []{};
        }

        virtual bool Connect(uint32_t peerAddress, uint16_t peerPort) override {
            return true;
        }

        virtual bool Process(
            MessageReceivedDelegate messageReceivedDelegate,
            BrokenDelegate brokenDelegate
        ) override {
            return true;
        }

        virtual uint32_t GetPeerAddress() const override{
            return 0;
        }

        virtual uint16_t GetPeerPort() const override {
            return 0;
        }

        virtual bool IsConnected() const override {
            return true;
        }

        virtual uint32_t GetBoundAddress() const override {
            return 0;
        }

        virtual uint16_t GetBoundPort() const override {
            return 0;
        }

        virtual void SendMessage(const std::vector< uint8_t >& message) override {
            messageSent = message;
        }

        virtual void Close(bool clean = false) override {
        }
    };

}

/**
 * This is the test fixture for these tests, providing common
 * setup and teardown for each test.
 */
struct ConnectionTests
    : public ::testing::Test
{
    // Properties

    /**
     * This holds any state in the mock shim layer representing
     * the TLS library.
     */
    MockTls mockTls;

    /**
     * This is the unit under test.
     */
    TwitchNetworkTransport::Connection connection;

    /**
     * This is a real network server used to test that the unit under test
     * can actually connect to a real server.
     */
    SystemAbstractions::NetworkEndpoint server;

    /**
     * This flag is used to tell the test fixture if we
     * moved the unit under test.
     */
    bool transportWasMoved = false;

    /**
     * These are the diagnostic messages that have been
     * received from the unit under test.
     */
    std::vector< std::string > diagnosticMessages;

    /**
     * This is the delegate obtained when subscribing
     * to receive diagnostic messages from the unit under test.
     * It's called to terminate the subscription.
     */
    SystemAbstractions::DiagnosticsSender::UnsubscribeDelegate diagnosticsUnsubscribeDelegate;

    /**
     * If this flag is set, we will print all received diagnostic
     * messages, in addition to storing them.
     */
    bool printDiagnosticMessages = false;

    /**
     * This collects information about any connections
     * established (presumably by the unit under test) to the server.
     */
    std::vector< Client > clients;

    /**
     * This holds any data received from the server.
     */
    std::vector< uint8_t > dataReceived;

    /**
     * This flag indicates whether or not the connection to the server
     * was broken by the server.
     */
    bool broken = false;

    /**
     * This is used to wake up threads which may be waiting for some
     * state in the fixture to be changed.
     */
    std::condition_variable_any waitCondition;

    /**
     * This is used to synchronize access to the object.
     */
    std::mutex mutex;

    // Methods

    /**
     * This method waits for the given number of connections to be established
     * with the server.
     *
     * @param[in] numConnections
     *     This is the number of connections to await.
     *
     * @return
     *     An indication of whether or not the given number of connections
     *     were established with the server before a reasonable amount of
     *     time has elapsed is returned.
     */
    bool AwaitConnections(size_t numConnections) {
        std::unique_lock< std::mutex > lock(mutex);
        return waitCondition.wait_for(
            lock,
            std::chrono::seconds(1),
            [this, numConnections]{
                return (clients.size() >= numConnections);
            }
        );
    }

    /**
     * This method waits for the server to break the connection
     * to the unit under test.
     *
     * @return
     *     An indication of whether or not the server breaks their
     *     end of the connection before a reasonable amount of
     *     time has elapsed is returned.
     */
    bool AwaitServerBreak() {
        std::unique_lock< std::mutex > lock(mutex);
        return waitCondition.wait_for(
            lock,
            std::chrono::seconds(1),
            [this]{
                return broken;
            }
        );
    }

    /**
     * This method waits for the client to break the connection
     * at the given index of the collection of connections
     * currently established with the server.
     *
     * @param[in] connectionIndex
     *     This is the index of the connection for which to await
     *     a client-side break.
     *
     * @return
     *     An indication of whether or not the client breaks their
     *     end of the connection before a reasonable amount of
     *     time has elapsed is returned.
     */
    bool AwaitClientBreak(size_t connectionIndex) {
        std::unique_lock< std::mutex > lock(mutex);
        return waitCondition.wait_for(
            lock,
            std::chrono::seconds(1),
            [this, connectionIndex]{
                return clients[connectionIndex].broken;
            }
        );
    }

    /**
     * This method waits for the server to send the given number
     * of bytes to the unit under test.
     *
     * @param[in] amount
     *     This is the number of bytes to await.
     *
     * @return
     *     An indication of whether or not the server has sent
     *     the given number of bytes before a reasonable amount of
     *     time has elapsed is returned.
     */
    bool AwaitServerData(size_t amount) {
        std::unique_lock< std::mutex > lock(mutex);
        return waitCondition.wait_for(
            lock,
            std::chrono::seconds(1),
            [this, amount]{
                return (dataReceived.size() >= amount);
            }
        );
    }

    /**
     * This method waits for the client to send the given number
     * of bytes through the connection at the given index of the
     * collection of connections currently established with the server.
     *
     * @param[in] connectionIndex
     *     This is the index of the connection for which to await
     *     data from the client.
     *
     * @param[in] amount
     *     This is the number of bytes to await.
     *
     * @return
     *     An indication of whether or not the client has sent
     *     the given number of bytes before a reasonable amount of
     *     time has elapsed is returned.
     */
    bool AwaitClientData(
        size_t connectionIndex,
        size_t amount
    ) {
        std::unique_lock< std::mutex > lock(mutex);
        return waitCondition.wait_for(
            lock,
            std::chrono::seconds(1),
            [this, connectionIndex, amount]{
                return (clients[connectionIndex].dataReceived.size() >= amount);
            }
        );
    }

    // ::testing::Test

    virtual void SetUp() {
        TlsDecorator::selectedTlsShim = &mockTls;
        diagnosticsUnsubscribeDelegate = connection.SubscribeToDiagnostics(
            [this](
                std::string senderName,
                size_t level,
                std::string message
            ){
                diagnosticMessages.push_back(
                    SystemAbstractions::sprintf(
                        "%s[%zu]: %s",
                        senderName.c_str(),
                        level,
                        message.c_str()
                    )
                );
                if (printDiagnosticMessages) {
                    printf(
                        "%s[%zu]: %s\n",
                        senderName.c_str(),
                        level,
                        message.c_str()
                    );
                }
            },
            0
        );
        const auto newConnectionDelegate = [this](
            std::shared_ptr< SystemAbstractions::NetworkConnection > newConnection
        ){
            std::unique_lock< decltype(mutex) > lock(mutex);
            size_t connectionIndex = clients.size();
            if (
                newConnection->Process(
                    [this, connectionIndex](const std::vector< uint8_t >& data){
                        std::unique_lock< decltype(mutex) > lock(mutex);
                        auto& dataReceived = clients[connectionIndex].dataReceived;
                        dataReceived.insert(
                            dataReceived.end(),
                            data.begin(),
                            data.end()
                        );
                        waitCondition.notify_all();
                    },
                    [this, connectionIndex](bool graceful){
                        std::unique_lock< decltype(mutex) > lock(mutex);
                        auto& broken = clients[connectionIndex].broken;
                        broken = true;
                        waitCondition.notify_all();
                    }
                )
            ) {
                Client newClient;
                newClient.connection = newConnection;
                clients.push_back(std::move(newClient));
                waitCondition.notify_all();
            }
        };
        const auto packetReceivedDelegate = [](
            uint32_t address,
            uint16_t port,
            const std::vector< uint8_t >& body
        ){
        };
        ASSERT_TRUE(
            server.Open(
                newConnectionDelegate,
                packetReceivedDelegate,
                SystemAbstractions::NetworkEndpoint::Mode::Connection,
                0x7F000001,
                0,
                0
            )
        );
        connection.SetCaCerts("PogChamp");
        connection.SetServerInfo("localhost", server.GetBoundPort());
        connection.SetMessageReceivedDelegate(
            [this](
                const std::string& message
            ){
                std::lock_guard< std::mutex > lock(mutex);
                dataReceived.insert(
                    dataReceived.end(),
                    message.begin(),
                    message.end()
                );
                waitCondition.notify_all();
            }
        );
        connection.SetDisconnectedDelegate(
            [this](){
                std::lock_guard< std::mutex > lock(mutex);
                broken = true;
                waitCondition.notify_all();
            }
        );
    }

    virtual void TearDown() {
        server.Close();
        clients.clear();
        if (!transportWasMoved) {
            diagnosticsUnsubscribeDelegate();
        }
        connection.Disconnect();
    }
};

TEST_F(ConnectionTests, Connect) {
    const auto connected = connection.Connect();
    ASSERT_TRUE(connected);
    ASSERT_TRUE(AwaitConnections(1));
    ASSERT_TRUE(mockTls.Await([this]{ return mockTls.tlsHandshakeCalled; }));
    ASSERT_EQ("PogChamp", mockTls.caCerts);
}

TEST_F(ConnectionTests, DisconnectWhenNotConnectedShouldNotCrash) {
    connection.Disconnect();
}

TEST_F(ConnectionTests, BreakClientSide) {
    (void)connection.Connect();
    ASSERT_TRUE(AwaitConnections(1));
    ASSERT_TRUE(mockTls.Await([this]{ return mockTls.tlsHandshakeCalled; }));
    connection.Disconnect();
    ASSERT_TRUE(AwaitClientBreak(0));
}

TEST_F(ConnectionTests, BreakServerSide) {
    (void)connection.Connect();
    ASSERT_TRUE(AwaitConnections(1));
    ASSERT_TRUE(mockTls.Await([this]{ return mockTls.tlsHandshakeCalled; }));
    clients[0].connection->Close(false);
    ASSERT_TRUE(AwaitServerBreak());
}

TEST_F(ConnectionTests, ClientSend) {
    (void)connection.Connect();
    ASSERT_TRUE(AwaitConnections(1));
    ASSERT_TRUE(mockTls.Await([this]{ return mockTls.tlsHandshakeCalled; }));
    const std::string testData("Hello, World!");
    const std::vector< uint8_t > testDataAsBytes(
        testData.begin(),
        testData.end()
    );
    const std::vector< uint8_t > dataWeExpectServerToReceive{ 1, 2, 3, 4, 5 };
    mockTls.tlsWriteEncryptedBuf = dataWeExpectServerToReceive;
    connection.Send(testData);
    ASSERT_TRUE(AwaitClientData(0, dataWeExpectServerToReceive.size()));
    EXPECT_EQ(testDataAsBytes, mockTls.tlsWriteDecryptedBuf);
    EXPECT_EQ(dataWeExpectServerToReceive, clients[0].dataReceived);
}

TEST_F(ConnectionTests, ServerSend) {
    (void)connection.Connect();
    ASSERT_TRUE(AwaitConnections(1));
    ASSERT_TRUE(mockTls.Await([this]{ return mockTls.tlsHandshakeCalled; }));
    const std::string testData("Hello, World!");
    const std::vector< uint8_t > testDataAsBytes(
        testData.begin(),
        testData.end()
    );
    const std::vector< uint8_t > dataWeExpectClientToReceive{ 1, 2, 3, 4, 5 };
    mockTls.tlsReadDecryptedBuf = dataWeExpectClientToReceive;
    clients[0].connection->SendMessage(testDataAsBytes);
    ASSERT_TRUE(AwaitServerData(dataWeExpectClientToReceive.size()));
    EXPECT_EQ(dataWeExpectClientToReceive, dataReceived);
}
