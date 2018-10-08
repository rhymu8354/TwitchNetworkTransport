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
        SystemAbstractions::NetworkConnection adaptee;

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
        TlsDecorator::TlsDecorator tls;

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

    Connection::~Connection() noexcept = default;

    Connection::Connection()
        : impl_(new Impl)
    {
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
        const auto connected = impl_->adaptee.Connect(
            address,
            impl_->portNumber
        );
        if (!connected) {
            return false;
        }
        const auto processing = impl_->adaptee.Process(
            std::bind(&Impl::OnMessageReceived, impl_.get(), std::placeholders::_1),
            std::bind(&Impl::OnConnectionBroken, impl_.get())
        );
        if (!processing) {
            impl_->adaptee.Close();
        }
        return processing;
    }

    void Connection::Disconnect() {
        impl_->adaptee.Close(false);
    }

    void Connection::Send(const std::string& message) {
        impl_->adaptee.SendMessage(
            std::vector< uint8_t >(
                message.begin(),
                message.end()
            )
        );
    }

}
