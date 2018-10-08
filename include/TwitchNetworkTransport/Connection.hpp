#ifndef TWITCH_NETWORK_TRANSPORT_CONNECTION_HPP
#define TWITCH_NETWORK_TRANSPORT_CONNECTION_HPP

/**
 * @file Connection.hpp
 *
 * This module declares the TwitchNetworkTransport::Connection
 * class.
 *
 * © 2018 by Richard Walters
 */

#include <functional>
#include <memory>
#include <Twitch/Connection.hpp>
#include <stdint.h>
#include <string>
#include <SystemAbstractions/DiagnosticsSender.hpp>
#include <SystemAbstractions/INetworkConnection.hpp>

namespace TwitchNetworkTransport {

    /**
     * This class is an adapter between three related classes in different
     * libraries:
     * - Twitch::Connection -- the interface required by the Twitch library
     *   for sending and receiving data across the transport layer.
     * - TlsDecorator::TlsDecorator -- the class which adds Transport Layer
     *   Security to a network connection.
     * - SystemAbstractions::NetworkConnection -- the class which implements
     *   a connection object in terms of the operating system's network APIs.
     */
    class Connection
        : public Twitch::Connection
    {
        // Lifecycle management
    public:
        ~Connection() noexcept;
        Connection(const Connection&) = delete;
        Connection(Connection&&) noexcept = delete;
        Connection& operator=(const Connection&) = delete;
        Connection& operator=(Connection&&) noexcept = delete;

        // Public methods
    public:
        /**
         * This is the default constructor.
         */
        Connection();

        /**
         * This method forms a new subscription to diagnostic
         * messages published by the transport.
         *
         * @param[in] delegate
         *     This is the function to call to deliver messages
         *     to the subscriber.
         *
         * @param[in] minLevel
         *     This is the minimum level of message that this subscriber
         *     desires to receive.
         *
         * @return
         *     A function is returned which may be called
         *     to terminate the subscription.
         */
        SystemAbstractions::DiagnosticsSender::UnsubscribeDelegate SubscribeToDiagnostics(
            SystemAbstractions::DiagnosticsSender::DiagnosticMessageDelegate delegate,
            size_t minLevel = 0
        );

        /**
         * This method is used to override the host name and port number
         * of the Twitch server.  You might want to do this, for example,
         * when testing this class, in order to have it connect to a test
         * server and not the real Twitch server.
         *
         * @param[in] hostNameOrAddress
         *     This is the host name or IP address (in string format) of
         *     the server to which to connect.
         *
         * @param[in] portNumber
         *     This is the TCP port number of the server to which to connect.
         */
        void SetServerInfo(
            const std::string& hostNameOrAddress,
            uint16_t portNumber
        );

        /**
         * This method is called to configure the adapter with the root
         * Certificate Authority (CA) certificates to trust, in PEM format.
         *
         * @param[in] caCerts
         *     This is the concatenation of the root Certificate Authority
         *     (CA) certificates to trust, in PEM format.
         */
        void SetCaCerts(const std::string& caCerts);

        // Twitch::Connection
    public:
        virtual void SetMessageReceivedDelegate(MessageReceivedDelegate messageReceivedDelegate) override;
        virtual void SetDisconnectedDelegate(DisconnectedDelegate disconnectedDelegate) override;
        virtual bool Connect() override;
        virtual void Disconnect() override;
        virtual void Send(const std::string& message) override;

        // Private properties
    private:
        /**
         * This is the type of structure that contains the private
         * properties of the instance.  It is defined in the implementation
         * and declared here to ensure that it is scoped inside the class.
         */
        struct Impl;

        /**
         * This contains the private properties of the instance.
         */
        std::unique_ptr< Impl > impl_;
    };

}

#endif /* TWITCH_NETWORK_TRANSPORT_CONNECTION_HPP */
