using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;

namespace Socklient {
    enum Method : byte {
        NoAuthentication = 0x00,
        UsernamePassword = 0x02
    }

    enum Command : byte {
        Connect = 0x01,
        /// <summary>
        /// Unsupported yet
        /// </summary>
        Bind = 0x02,
        UdpAssociate = 0x03
    }

    enum AddressType : byte {
        IPv4 = 0x01,
        Domain = 0x03,
        IPv6 = 0x04
    }

    enum SocksStatus {
        /// <summary>
        /// Before handshake and authentication.
        /// </summary>
        Initial,
        /// <summary>
        /// After handshake, authentication, and send <see cref="Command.Connect"/> or <see cref="Command.UdpAssociate"/> command.
        /// </summary>
        Connected,
        /// <summary>
        /// Disposed, can not reuse.
        /// </summary>
        Disposed
    }

    /// <summary>
    /// Indicates the reply code of the server to the request.
    /// </summary>
    public enum Reply : byte {
        /// <summary>
        /// Succeeded.
        /// </summary>
        Successed = 0x00,
        /// <summary>
        /// General SOCKS server failure.
        /// </summary>
        GeneralFailure = 0x01,
        /// <summary>
        /// Connection not allowed by ruleset.
        /// </summary>
        ConnectionNotAllowed = 0x02,
        /// <summary>
        /// Network unreachable.
        /// </summary>
        NetworkUnreachable = 0x03,
        /// <summary>
        /// Host unreachable.
        /// </summary>
        HostUnreachable = 0x04,
        /// <summary>
        /// Connection refused.
        /// </summary>
        ConnectionRefused = 0x05,
        /// <summary>
        /// TTL expired.
        /// </summary>
        TTLExpired = 0x06,
        /// <summary>
        /// Command not supported.
        /// </summary>
        CommandNotSupported = 0x07,
        /// <summary>
        /// Address type not supported.
        /// </summary>
        AddressTypeNotSupported = 0x08
    }

    /// <summary>
    /// Determine the behavior when the client receive a <see cref="AddressType.Domain"/> ATYP.
    /// </summary>
    public enum DomainAddressBehavior {
        /// <summary>
        /// Throw a <see cref="ProtocolErrorException"/>.
        /// </summary>
        ThrowException,
        /// <summary>
        /// Use the <see cref="SocksClient.TcpClient"/> connected remote address as BND.ADDR. 
        /// It is usually the address of the server specified when calling ConnectAsync or UdpAssociateAsync.
        /// </summary>
        UseConnectedAddress
    }
}
