﻿using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Socklient {
    /// <summary>
    /// A SOCKS5 client.
    /// </summary>
    public sealed class SocksClient : IDisposable {
        /// <summary>
        /// The BND.ADDR field of the response from server.
        /// </summary>
        /// <exception cref="InvalidOperationException">The <see cref="SocksClient"/> is not connected or associated.</exception>
        public IPAddress BoundAddress => _boundAddress ?? throw new InvalidOperationException($"The {GetType().FullName} is not connected or associated.");
        private IPAddress? _boundAddress;

        /// <summary>
        /// The BND.PORT field of the response from server.
        /// </summary>
        /// <exception cref="InvalidOperationException">The <see cref="SocksClient"/> is not connected or associated.</exception>
        public int BoundPort => _boundPort ?? throw new InvalidOperationException($"The {GetType().FullName} is not connected or associated.");
        private int? _boundPort;

        /// <summary>
        /// Get underlying <see cref="System.Net.Sockets.TcpClient"/> for more fine-grained control in CONNECT mode.
        /// </summary>
        public TcpClient TcpClient { get; private set; } = new TcpClient();

        /// <summary>
        /// Get underlying <see cref="System.Net.Sockets.UdpClient"/> for more fine-grained control in UDP-ASSOCIATE mode.
        /// This property is null in CONNECT mode. 
        /// </summary>
        public UdpClient? UdpClient { get; private set; }

        private const byte Version = 0x5;
        private const byte AuthenticationVersion = 0x1;
        private const byte UsernameMaxLength = 255;
        private const byte PasswordMaxLength = 255;
        private const byte IPv4AddressLength = 4;
        private const byte DomainMaxLength = 255;
        private const byte IPv6AddressLength = 16;

        private readonly IPAddress? _serverAddress;
        private readonly string? _serverHost;
        private readonly int _serverPort;
        private readonly NetworkCredential? _credential;
        private NetworkStream? _stream;
        private SocksStatus _status = SocksStatus.Initial;

        /// <summary>
        /// Initializes a new instance of <see cref="SocksClient"/> with the specified SOCKS5 <paramref name="server"/> and 
        /// <paramref name="port"/>, <paramref name="credential"/> is optional.
        /// </summary>
        /// <param name="server">The address of the SOCKS5 server.</param>
        /// <param name="port">The port of the SOCKS5 server.</param>
        /// <param name="credential">Optional credential for username/password authentication.</param>
        public SocksClient(IPAddress server, int port, NetworkCredential? credential = null) {
            _serverAddress = server ?? throw new ArgumentNullException(nameof(server));
            _serverPort = port;
            _credential = credential;

            if (credential?.UserName.Length > UsernameMaxLength)
                throw new ArgumentOutOfRangeException($"The {nameof(credential)}.{nameof(credential.UserName)} is longer than {UsernameMaxLength}");
            if (credential?.Password.Length > PasswordMaxLength)
                throw new ArgumentOutOfRangeException($"The {nameof(credential)}.{nameof(credential.Password)} is longer than {PasswordMaxLength}");
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SocksClient"/> with the specified SOCKS5 <paramref name="server"/> and 
        /// <paramref name="port"/>, <paramref name="credential"/> is optional.
        /// </summary>
        /// <param name="server">The hostname of the SOCKS5 server.</param>
        /// <param name="port">The port of the SOCKS5 server.</param>
        /// <param name="credential">Optional credential for username/password authentication.</param>
        public SocksClient(string server, int port, NetworkCredential? credential = null) {
            _serverHost = server ?? throw new ArgumentNullException(nameof(server));
            _serverPort = port;
            _credential = credential;

            if (credential != null && Encoding.UTF8.GetByteCount(credential.UserName) > UsernameMaxLength)
                throw new ArgumentOutOfRangeException($"The {nameof(credential)}.{nameof(credential.UserName)} is longer than {UsernameMaxLength} after converted to UTF-8 bytes.");
            if (credential != null && Encoding.UTF8.GetByteCount(credential.Password) > PasswordMaxLength)
                throw new ArgumentOutOfRangeException($"The {nameof(credential)}.{nameof(credential.Password)} is longer than {PasswordMaxLength} after converted to UTF-8 bytes.");
        }

        /// <summary>
        /// Dispose the underlying <see cref="TcpClient"/> and <see cref="UdpClient"/>.
        /// </summary>
        public void Dispose() {
            if (_status != SocksStatus.Disposed) {
                TcpClient.Dispose();
                UdpClient?.Dispose();
                _stream?.Dispose();

                _status = SocksStatus.Disposed;
            }
        }

        /// <summary>
        /// Do handshake and authentication (if need), then send a <see cref="Command.Connect"/> command to the SOCKS5 server.
        /// </summary>
        /// <param name="address">The destination address to communicating via SOCKS5 server.</param>
        /// <param name="port">The destination port to communicating via SOCKS5 server.</param>
        /// <param name="token">The token to monitor for cancellation. The default value is <see cref="CancellationToken.None"/>.</param>
        public async Task ConnectAsync(IPAddress address, int port, CancellationToken token = default) {
            if (address is null)
                throw new ArgumentNullException(nameof(address));
            if (_status == SocksStatus.Connected)
                throw new InvalidOperationException($"{GetType().FullName} already connected or associated.");
            if (_status == SocksStatus.Disposed)
                throw new ObjectDisposedException(GetType().FullName);

            await PrepareAsync(token);
            await SendCommandAsync(Command.Connect, null, address, port, token);

            _status = SocksStatus.Connected;
        }

        /// <summary>
        /// Do handshake and authentication (if need), then send a <see cref="Command.Connect"/> command to the SOCKS5 server.
        /// </summary>
        /// <param name="domain">The destination domain to communicating via SOCKS5 server.</param>
        /// <param name="port">The destination port to communicating via SOCKS5 server.</param>
        /// <param name="token">The token to monitor for cancellation. The default value is <see cref="CancellationToken.None"/>.</param>
        public async Task ConnectAsync(string domain, int port, CancellationToken token = default) {
            if (domain is null)
                throw new ArgumentNullException(nameof(domain));
            if (Encoding.UTF8.GetByteCount(domain) > DomainMaxLength)
                throw new ArgumentOutOfRangeException(nameof(domain), $"The {nameof(domain)} is longer than {DomainMaxLength} after converted to UTF-8 bytes.");
            if (_status == SocksStatus.Connected)
                throw new InvalidOperationException($"{GetType().FullName} already connected or associated.");
            if (_status == SocksStatus.Disposed)
                throw new ObjectDisposedException(GetType().FullName);

            await PrepareAsync(token);
            await SendCommandAsync(Command.Connect, domain, null, port, token);

            _status = SocksStatus.Connected;
        }

        /// <summary>
        /// Get the <see cref="NetworkStream"/> of the underlying <see cref="TcpClient"/>.
        /// </summary>
        public NetworkStream GetStream() {
            if (_status == SocksStatus.Disposed)
                throw new ObjectDisposedException(GetType().FullName);
            if (_status != SocksStatus.Connected)
                throw new InvalidOperationException($"The {GetType().FullName} is not connected or associated.");

            return _stream!;
        }

        /// <summary>
        /// Do handshake and authentication (if need), then send a <see cref="Command.UdpAssociate"/> command to the SOCKS5 server.
        /// <para>
        /// The <paramref name="address"/> and <paramref name="port"/> fields contain the address and port that the client expects to use to send UDP datagrams on for the association. The server MAY use this information to limit access to the association. If the client is not in possesion of the information at the time of UDP Associate (for example, all personal users are NAT, there is no way to determine the public IP and port they will use before sending), the client MUST use a port number and address of all zeros.
        /// </para>
        /// </summary>
        /// <param name="address">The address that the client expects to use to send UDP datagrams on for the association. Alias of DST.ADDR defined in RFC 1928 UDP Associate.</param>
        /// <param name="port">The port that the client expects to use to send UDP datagrams on for the association. Alias of DST.PORT defined in RFC 1928 UDP Associate.</param>
        /// <param name="token">The token to monitor for cancellation. The default value is <see cref="CancellationToken.None"/>.</param>
        public async Task UdpAssociateAsync(IPAddress address, int port, CancellationToken token = default) {
            if (_status == SocksStatus.Connected)
                throw new InvalidOperationException($"{GetType().FullName} already connected or associated.");
            if (_status == SocksStatus.Disposed)
                throw new ObjectDisposedException(GetType().FullName);

            await PrepareAsync(token);
            await SendCommandAsync(Command.UdpAssociate, null, address, port, token);

            UdpClient = new UdpClient(port, address.AddressFamily);
            UdpClient.Connect(BoundAddress, BoundPort);

            _status = SocksStatus.Connected;
        }

        /// <summary>
        /// Send datagram to destination domain and port via SOCKS server.
        /// </summary>
        /// <param name="datagram">The datagram to send.</param>
        /// <param name="domain">The destination domain.</param>
        /// <param name="port">The destination port.</param>
        public Task SendAsync(ReadOnlyMemory<byte> datagram, string domain, int port) {
            if (domain is null)
                throw new ArgumentNullException(nameof(domain));

            return SendAsync(datagram, domain, address: null, port);
        }

        /// <summary>
        /// Send datagram to destination address and port via SOCKS server.
        /// </summary>
        /// <param name="datagram">The datagram to send.</param>
        /// <param name="address">The destination address.</param>
        /// <param name="port">The destination port.</param>
        public Task SendAsync(ReadOnlyMemory<byte> datagram, IPAddress address, int port) {
            if (address is null)
                throw new ArgumentNullException(nameof(address));

            return SendAsync(datagram, domain: null, address, port);
        }

        private async Task SendAsync(ReadOnlyMemory<byte> data, string? domain, IPAddress? address, int port) {
            if (UdpClient == null)
                throw new InvalidOperationException($"The {GetType().FullName} is not associated.");
            if (_status == SocksStatus.Disposed)
                throw new ObjectDisposedException(GetType().FullName);

            // +-----+------+------+----------+----------+----------+
            // | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            // +-----+------+------+----------+----------+----------+
            // |  2  |  1   |  1   | Variable |    2     | Variable |
            // +-----+------+------+----------+----------+----------+
            var addressLength = GetAddressLength(domain, address);
            var bufferLength = 2 + 1 + 1 + (domain != null ? 1 : 0) + addressLength + 2 + data.Length;
            var buffer = ArrayPool<byte>.Shared.Rent(bufferLength);

            try {
                buffer[0] = buffer[1] = buffer[2] = 0;
                WriteAddressInfo(addressLength, domain, address, port, buffer, 3);
                data.Span.CopyTo(buffer.AsSpan(bufferLength - data.Length));

                await UdpClient.SendAsync(buffer, bufferLength);

            } finally {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        /// <summary>
        /// Receive datagram via SOCKS server.
        /// </summary>
        public async Task<UdpReceiveMemory> ReceiveAsync() {
            if (UdpClient == null)
                throw new InvalidOperationException($"The {GetType().FullName} is not associated.");
            if (_status == SocksStatus.Disposed)
                throw new ObjectDisposedException(GetType().FullName);

            // +-----+------+------+----------+----------+----------+
            // | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            // +-----+------+------+----------+----------+----------+
            // |  2  |  1   |  1   | Variable |    2     | Variable |
            // +-----+------+------+----------+----------+----------+
            // |                  HEADER                 |          |
            // +----------------------------------------------------+
            var result = await UdpClient.ReceiveAsync();
            var buffer = result.Buffer;
            if (buffer.Length < 4)
                ThrowBufferTooSmall(buffer);

            var isIPv6 = (AddressType)buffer[3] switch {
                AddressType.IPv4 => false,
                AddressType.IPv6 => true,
                _ => throw new ProtocolErrorException($"Server replies unexpected ATYP: 0x{buffer[3]:X2}.")
            };

            var headerLength = 4 + (isIPv6 ? IPv6AddressLength : IPv4AddressLength) + 2;
            if (buffer.Length <= headerLength)
                ThrowBufferTooSmall(buffer);

            var (address, port) = ReadAddressInfo(isIPv6, buffer.AsSpan(4, headerLength - 4));

            return new UdpReceiveMemory(buffer.AsMemory(headerLength), new IPEndPoint(address, port));
        }

        private async Task PrepareAsync(CancellationToken token) {
            token.ThrowIfCancellationRequested();

            if (_serverAddress != null)
                await TcpClient.ConnectAsync(_serverAddress, _serverPort);
            else if (_serverHost != null)
                await TcpClient.ConnectAsync(_serverHost, _serverPort);

            _stream ??= TcpClient.GetStream();

            var method = await HandshakeAsync(_credential == null ?
                new[] { Method.NoAuthentication } :
                new[] { Method.NoAuthentication, Method.UsernamePassword }, token);

            if (method == Method.UsernamePassword)
                await AuthenticateAsync(token);
        }

        private async Task<Method> HandshakeAsync(Method[] methods, CancellationToken token) {
            // +-----+----------+----------+
            // | VER | NMETHODS | METHODS  |
            // +-----+----------+----------+
            // |  1  |    1     | 1 to 255 |
            // +-----+----------+----------+
            var requestLength = 1 + 1 + methods.Length;
            var buffer = ArrayPool<byte>.Shared.Rent(requestLength);

            try {
                buffer[0] = Version;
                buffer[1] = (byte)methods.Length;
                MemoryMarshal.AsBytes<Method>(methods).CopyTo(buffer.AsSpan(2, requestLength));

                await _stream!.WriteAsync(buffer, 0, requestLength, token);

                // +-----+--------+
                // | VER | METHOD |
                // +-----+--------+
                // |  1  |   1    |
                // +-----+--------+
                await _stream.ReadRequiredAsync(buffer, 0, 2, token);

                if (buffer[0] != Version)
                    throw new ProtocolErrorException($"Server replies incompatible version: 0x{buffer[0]:X2}.");

                var serverMethod = (Method)buffer[1];
                if (!Enum.IsDefined(typeof(Method), serverMethod))
                    throw new ProtocolErrorException($"Server replies unsupported authentication method: 0x{(byte)serverMethod:X2}.");

                if (_credential == null && serverMethod == Method.UsernamePassword)
                    throw new ProtocolErrorException($"Server replies unexpected authentication method: {serverMethod}.");

                return serverMethod;

            } finally {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private async Task AuthenticateAsync(CancellationToken token) {
            // +-----+------+----------+------+----------+
            // | VER | ULEN |  UNAME   | PLEN |  PASSWD  |
            // +-----+------+----------+------+----------+
            // |  1  |  1   | 1 to 255 |  1   | 1 to 255 |
            // +-----+------+----------+------+----------+
            var usernameLength = (byte)Encoding.UTF8.GetByteCount(_credential!.UserName);
            var passwordLength = (byte)Encoding.UTF8.GetByteCount(_credential.Password);
            var requestLength = 1 + 1 + usernameLength + 1 + passwordLength;
            var buffer = ArrayPool<byte>.Shared.Rent(requestLength);

            try {
                buffer[0] = AuthenticationVersion;
                buffer[1] = usernameLength;
                var bytesCount = Encoding.UTF8.GetBytes(_credential.UserName, 0, _credential.UserName.Length, buffer, 2);
                buffer[2 + bytesCount] = passwordLength;
                Encoding.UTF8.GetBytes(_credential.Password, 0, _credential.Password.Length, buffer, 2 + bytesCount + 1);

                await _stream!.WriteAsync(buffer, 0, requestLength, token);

                // +-----+--------+
                // | VER | STATUS |
                // +-----+--------+
                // |  1  |   1    |
                // +-----+--------+
                await _stream.ReadRequiredAsync(buffer, 0, 2, token);

                if (buffer[1] != 0)
                    throw new AuthenticationException($"Authentication failure with status code: 0x{buffer[1]:X}.");

            } finally {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private async Task SendCommandAsync(Command command, string? domain, IPAddress? address, int port, CancellationToken token) {
            // +-----+-----+-------+------+----------+----------+
            // | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            // +-----+-----+-------+------+----------+----------+
            // |  1  |  1  | X'00' |  1   | Variable |    2     |
            // +-----+-----+-------+------+----------+----------+
            var addressLength = GetAddressLength(domain, address);
            var requestLength = 1 + 1 + 1 + 1 + (domain != null ? 1 : 0) + addressLength + 2;
            var buffer = ArrayPool<byte>.Shared.Rent(requestLength);

            try {
                buffer[0] = Version;
                buffer[1] = (byte)command;
                buffer[2] = 0;
                WriteAddressInfo(addressLength, domain, address, port, buffer, 3);

                await _stream!.WriteAsync(buffer, 0, requestLength, token);

                // +-----+-----+-------+------+----------+----------+
                // | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
                // +-----+-----+-------+------+----------+----------+
                // |  1  |  1  | X'00' |  1   | Variable |    2     |
                // +-----+-----+-------+------+----------+----------+
                var responseLengthV4 = 1 + 1 + 1 + 1 + IPv4AddressLength + 2;
                var responseLengthV6 = 1 + 1 + 1 + 1 + IPv6AddressLength + 2;
                if (buffer.Length < responseLengthV6) {
                    ArrayPool<byte>.Shared.Return(buffer);
                    buffer = ArrayPool<byte>.Shared.Rent(responseLengthV6);
                }

                // First we assume it is IPv4, and if the assumption is correct, we can do the read operation only once. 
                // If not, read more for IPv6.
                await _stream!.ReadRequiredAsync(buffer, 0, responseLengthV4, token);

                var isIPv6 = (AddressType)buffer[3] switch {
                    AddressType.IPv4 => false,
                    AddressType.IPv6 => true,
                    _ => throw new ProtocolErrorException($"Server replies unexpected ATYP: 0x{buffer[3]:X2}.")
                };
                if (isIPv6)
                    await _stream.ReadRequiredAsync(buffer, responseLengthV4, IPv6AddressLength - IPv4AddressLength, token);

                (_boundAddress, _boundPort) = ReadAddressInfo(isIPv6, buffer.AsSpan(4));

            } finally {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private byte GetAddressLength(string? domain, IPAddress? address) {
            if (domain != null) {
                return (byte)Encoding.UTF8.GetByteCount(domain);

            } else {
                return address!.AddressFamily switch {
                    AddressFamily.InterNetwork => IPv4AddressLength,
                    AddressFamily.InterNetworkV6 => IPv6AddressLength,
                    _ => throw new ArgumentOutOfRangeException(nameof(address))
                };
            }
        }

        private void WriteAddressInfo(byte addressLength, string? domain, IPAddress? address, int port, byte[] buffer, int offset) {
            // +------+----------+------+
            // | ATYP |   ADDR   | PORT |
            // +------+----------+------+
            // |  1   | Variable |  2   |
            // +------+----------+------+
            buffer[offset++] = (byte)(domain != null ? AddressType.Domain : address!.AddressFamily.ToAddressType());
            if (domain != null) {
                buffer[offset++] = addressLength;
                offset += Encoding.UTF8.GetBytes(domain, 0, domain.Length, buffer, offset);

            } else {
#if NETSTANDARD2_0
                address!.GetAddressBytes().CopyTo(buffer.AsSpan(offset));
#elif NETSTANDARD2_1
                Debug.Assert(address!.TryWriteBytes(buffer.AsSpan(offset), out _));
#endif
                offset += addressLength;
            }

            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(offset), (ushort)port);
        }

        private (IPAddress Address, int Port) ReadAddressInfo(bool isIPv6, ReadOnlySpan<byte> buffer) {
            // +----------+------+
            // |   ADDR   | PORT |
            // +----------+------+
            // | Variable |  2   |
            // +----------+------+
            var addressLength = isIPv6 ? IPv6AddressLength : IPv4AddressLength;

#if NETSTANDARD2_0
            var address = new IPAddress(buffer.Slice(0, addressLength).ToArray());
#elif NETSTANDARD2_1
            var address = new IPAddress(buffer.Slice(0, addressLength));
#endif

            var port = BinaryPrimitives.ReadUInt16LittleEndian(buffer.Slice(addressLength, 2));

            return (address, port);
        }

        private static void ThrowBufferTooSmall(byte[] buffer) =>
            throw new ProtocolErrorException($"Server replies a packet that was smaller than expected: {BitConverter.ToString(buffer)}");
    }
}