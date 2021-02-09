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

    enum Reply : byte {
        Successed = 0x00,
        GeneralFailure = 0x01,
        ConnectionNotAllowed = 0x02,
        NetworkUnreachable = 0x03,
        HostUnreachable = 0x04,
        ConnectionRefused = 0x05,
        TTLExpired = 0x06,
        CommandNotSupported = 0x07,
        AddressTypeNotSupported = 0x08
    }

    enum SocksStatus {
        /// <summary>
        /// Before handshake and authentication.
        /// </summary>
        Initial,
        /// <summary>
        /// After handshake, authentication, and send <see cref="Command.Connect"/> command.
        /// </summary>
        Connected,
        /// <summary>
        /// Disposed, can not reuse.
        /// </summary>
        Disposed
    }
}
