using System;
using System.Collections.Generic;
using System.Text;

namespace SocklientDotNet {
    public enum Method : byte {
        NoAuthentication = 0x00,
        GSSAPI = 0x01,
        UsernamePassword = 0x02,
        NoAcceptable = 0xff
    }

    public enum Command : byte {
        Connect = 0x01,
        /// <summary>
        /// Unsupported yet
        /// </summary>
        Bind = 0x02,
        UdpAssociate = 0x03
    }

    public enum AddressType : byte {
        IPv4 = 0x01,
        Domain = 0x03,
        IPv6 = 0x04
    }

    public enum Reply : byte {
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

    public enum SocksStatus {
        /// <summary>
        /// Before handshake and authentication.
        /// </summary>
        Initial,
        /// <summary>
        /// After handshake and authentication, able to send data.
        /// </summary>
        Initialized,
        /// <summary>
        /// Connection closed, can not reuse.
        /// </summary>
        Closed
    }
}
