/**
 * @file Connection.cpp
 *
 * This module contains the implementation of the
 * TwitchNetworkTransport::Connection class.
 *
 * © 2018 by Richard Walters
 */

#include <functional>
#include <TlsDecorator/TlsDecorator.hpp>
#include <TwitchNetworkTransport/Connection.hpp>
#include <inttypes.h>
#include <mutex>
#include <stdint.h>
#include <string>
#include <SystemAbstractions/DiagnosticsSender.hpp>
#include <SystemAbstractions/NetworkConnection.hpp>
#include <SystemAbstractions/StringExtensions.hpp>
#include <vector>

namespace TwitchNetworkTransport {

    /**
     * This contains the private properties of a
     * Connection instance.
     */
    struct Connection::Impl {
        // Properties

        /**
         * This is a helper object used to generate and publish
         * diagnostic messages.
         */
        std::shared_ptr< SystemAbstractions::DiagnosticsSender > diagnosticsSender;

        /**
         * This is the object which is implementing the network
         * connection in terms of the operating system's network APIs.
         */
        std::shared_ptr< SystemAbstractions::NetworkConnection > adaptee;

        /**
         * This is the function to call whenever any message is received
         * from the Twitch server for the user agent.
         */
        MessageReceivedDelegate messageReceivedDelegate;

        /**
         * This is the function to call when the Twitch server closes
         * its end of the connection.
         */
        DisconnectedDelegate disconnectedDelegate;

        /**
         * This is the object which is providing security for the connection.
         */
        std::unique_ptr< TlsDecorator::TlsDecorator > tls;

        /**
         * This is the concatenation of the root Certificate Authority
         * (CA) certificates to trust, in PEM format.
         */
        std::string caCerts;

        /**
         * This is the host name or IP address (in string format) of
         * the server to which to connect.
         */
        std::string hostNameOrAddress = "irc.chat.twitch.tv";

        /**
         * This is the TCP port number of the server to which to connect.
         */
        uint16_t portNumber = 6697;

        // Methods

        /**
         * This is the constructor for the structure.
         */
        Impl()
            : diagnosticsSender(std::make_shared< SystemAbstractions::DiagnosticsSender >("Connection"))
        {
        }

        /**
         * This is called whenever more data is received from the peer
         * of the connection.
         *
         * @param[in] message
         *     This contains the data received from
         *     the peer of the connection.
         */
        void OnMessageReceived(const std::vector< uint8_t >& message) {
            if (messageReceivedDelegate != nullptr) {
                messageReceivedDelegate(
                    std::string(
                        message.begin(),
                        message.end()
                    )
                );
            }
        }

        /**
         * This is called whenever the connection is broken.
         */
        void OnConnectionBroken() {
            if (disconnectedDelegate != nullptr) {
                disconnectedDelegate();
            }
        }
    };

    Connection::~Connection() noexcept {
        Disconnect();
    }

    Connection::Connection()
        : impl_(new Impl)
    {
        impl_->adaptee = std::make_shared< SystemAbstractions::NetworkConnection >();
    }

    SystemAbstractions::DiagnosticsSender::UnsubscribeDelegate Connection::SubscribeToDiagnostics(
        SystemAbstractions::DiagnosticsSender::DiagnosticMessageDelegate delegate,
        size_t minLevel
    ) {
        return impl_->diagnosticsSender->SubscribeToDiagnostics(delegate, minLevel);
    }

    void Connection::SetServerInfo(
        const std::string& hostNameOrAddress,
        uint16_t portNumber
    ) {
        impl_->hostNameOrAddress = hostNameOrAddress;
        impl_->portNumber = portNumber;
    }

    void Connection::SetCaCerts(const std::string& caCerts) {
        impl_->caCerts = caCerts;
    }

    void Connection::SetMessageReceivedDelegate(MessageReceivedDelegate messageReceivedDelegate) {
        impl_->messageReceivedDelegate = messageReceivedDelegate;
    }

    void Connection::SetDisconnectedDelegate(DisconnectedDelegate disconnectedDelegate) {
        impl_->disconnectedDelegate = disconnectedDelegate;
    }

    bool Connection::Connect() {
        const uint32_t address = SystemAbstractions::NetworkConnection::GetAddressOfHost(impl_->hostNameOrAddress);
        if (address == 0) {
            return false;
        }
        std::unique_ptr< TlsDecorator::TlsDecorator > tls(new TlsDecorator::TlsDecorator());
        tls->ConfigureAsClient(
            impl_->adaptee,
            impl_->caCerts,
            impl_->hostNameOrAddress
        );
        const auto connected = tls->Connect(
            address,
            impl_->portNumber
        );
        if (!connected) {
            return false;
        }
        const auto processing = tls->Process(
            std::bind(&Impl::OnMessageReceived, impl_.get(), std::placeholders::_1),
            std::bind(&Impl::OnConnectionBroken, impl_.get())
        );
        if (!processing) {
            tls->Close();
        }
        impl_->tls = std::move(tls);
        return processing;
    }

    void Connection::Disconnect() {
        if (impl_->tls != nullptr) {
            impl_->tls->Close(false);
            impl_->tls.reset(nullptr);
        }
    }

    void Connection::Send(const std::string& message) {
        impl_->tls->SendMessage(
            std::vector< uint8_t >(
                message.begin(),
                message.end()
            )
        );
    }

}
