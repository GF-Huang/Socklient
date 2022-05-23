using System;
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
        public TcpClient TcpClient { get; } = new TcpClient();

        /// <summary>
        /// Get underlying <see cref="System.Net.Sockets.UdpClient"/> for more fine-grained control in UDP-ASSOCIATE mode.
        /// This property is null in CONNECT mode. 
        /// </summary>
        public UdpClient? UdpClient { get; private set; }

        /// <summary>
        /// Used to decide whether to ignore the BND.ADDR responded by UDP Associate command. Default return false.
        /// <para>
        /// In the Internet world, a considerable number of SOCKS5 servers have incorrect UDP Associate implementation. 
        /// </para>
        /// <para>
        /// According to the description of UDP Association in RFC 1928: "In the reply to a UDP ASSOCIATE request, the BND.PORT and BND.ADDR fields indicate the port number/address where the client MUST send UDP request messages to be relayed.", the server should respond its public IP address. If the server has multiple public IP addresses, the server should decide which public IP to respond according to its own strategy. 
        /// </para>
        /// <para>
        /// However, most SOCKS5 servers implementations are very rough. They often use some private addresses as BND.ADDR respond to the client, such as 10.0.0.1, 172.16.1.1, 192.168.1.1 and so on. In this case, the UDP packet sent by the client cannot reach the server at all, unless the client and the server are in the same LAN.
        /// </para>
        /// <para>
        /// Therefore, through this callback, the client can according to the received BND.ADDR to determine whether this address is a private address. If true is returned, the client will send UDP packet to ServerAddress:BND.PORT; If false is returned, it will send UDP packet to BND.ADDR:BND.PORT.
        /// </para>
        /// </summary>
        public ShouldIgnoreBoundAddressCallback ShouldIgnoreBoundAddressCallback { get; set; } = (s, a) => Task.FromResult(false);

        /// <summary>
        /// Determine the behavior when the client receive a <see cref="AddressType.Domain"/> ATYP. 
        /// The default value is <see cref="DomainAddressBehavior.ThrowException"/>.
        /// <para>
        /// Some SOCKS5 servers may hide the server's other IPs or other reasons, when responding to <see cref="Command.Connect"/> or <see cref="Command.UdpAssociate"/> request, they reply <see cref="AddressType.Domain"/>(0x03) as ATYP. 
        /// This property determines what behavior the client should take in this case.
        /// </para>
        /// <para>
        /// Note: This property only effects <see cref="Command.Connect"/> and <see cref="Command.UdpAssociate"/> request. 
        /// If UDP relay message header contains <see cref="AddressType.Domain"/>(0x03) ATYP, it will always throw a <see cref="ProtocolErrorException"/> exception.
        /// </para>
        /// </summary>
        public DomainAddressBehavior DomainAddressBehavior { get; set; } = DomainAddressBehavior.ThrowException;

        private IPAddress RemoteAddress => ((IPEndPoint)TcpClient.Client.RemoteEndPoint).Address;

        private const byte Version = 0x5;
        private const byte AuthenticationVersion = 0x1;
        private const byte UsernameMaxLength = 255;
        private const byte PasswordMaxLength = 255;
        private const byte IPv4AddressLength = 4;
        private const byte DomainLengthByteLength = 1;
        private const byte DomainMaxLength = 255;
        private const byte IPv6AddressLength = 16;
        private const byte PortLength = 2;
        private static readonly Method[] MethodsNoAuth = new[] { Method.NoAuthentication };
        private static readonly Method[] MethodsNoAuthUsernamePassword = new[] { Method.NoAuthentication, Method.UsernamePassword };

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

            await PrepareAsync(token).ConfigureAwait(false);
            await SendCommandAsync(Command.Connect, null, address, port, token).ConfigureAwait(false);

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

            await PrepareAsync(token).ConfigureAwait(false);
            await SendCommandAsync(Command.Connect, domain, null, port, token).ConfigureAwait(false);

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
        /// The <paramref name="address"/> and <paramref name="port"/> fields contain the address and port that the client expects to use to send UDP datagrams on for the association. The server MAY use this information to limit access to the association. If the client is not in possesion of the information at the time of UDP Associate (for example, most home users are behind NAT, there is no way to determine the public IP and port they will use before sending), the client MUST use a port number and address of all zeros.
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

            await PrepareAsync(token).ConfigureAwait(false);
            await SendCommandAsync(Command.UdpAssociate, null, address, port, token).ConfigureAwait(false);

            if (BoundAddress.Equals(IPAddress.Any) || BoundAddress.Equals(IPAddress.IPv6Any))
                _boundAddress = _serverAddress ?? RemoteAddress;
            if (BoundPort == 0)
                _boundPort = ((IPEndPoint)TcpClient.Client.RemoteEndPoint).Port;

            var ignoreBoundAddress = await ShouldIgnoreBoundAddressCallback(this, BoundAddress).ConfigureAwait(false);
            var addressToConnect = ignoreBoundAddress ? (_serverAddress ?? RemoteAddress) : BoundAddress;

            UdpClient = new UdpClient(AddressFamily.InterNetworkV6);
            UdpClient.Client.DualMode = true;
            UdpClient.Connect(addressToConnect, BoundPort);

            _status = SocksStatus.Connected;
        }

        /// <summary>
        /// Send datagram to destination domain and port via SOCKS server.
        /// </summary>
        /// <param name="datagram">The datagram to send.</param>
        /// <param name="domain">The destination domain.</param>
        /// <param name="port">The destination port.</param>
        public Task<int> SendAsync(ReadOnlyMemory<byte> datagram, string domain, int port) {
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
        public Task<int> SendAsync(ReadOnlyMemory<byte> datagram, IPAddress address, int port) {
            if (address is null)
                throw new ArgumentNullException(nameof(address));

            return SendAsync(datagram, domain: null, address, port);
        }

        private async Task<int> SendAsync(ReadOnlyMemory<byte> data, string? domain, IPAddress? address, int port) {
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
            var bufferLength = 2 + 1 + 1 + (domain != null ? DomainLengthByteLength : 0) + addressLength + PortLength + data.Length;
            var buffer = ArrayPool<byte>.Shared.Rent(bufferLength);

            try {
                buffer[0] = buffer[1] = buffer[2] = 0;
                WriteAddressInfo(addressLength, domain, address, port, buffer, 3);
                data.Span.CopyTo(buffer.AsSpan(bufferLength - data.Length));

                await UdpClient.SendAsync(buffer, bufferLength).ConfigureAwait(false);

                return bufferLength;

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
            var result = await UdpClient.ReceiveAsync().ConfigureAwait(false);
            var buffer = result.Buffer;
            if (buffer.Length < 4)
                ThrowBufferTooSmall(buffer);

            var isIPv6 = (AddressType)buffer[3] switch {
                AddressType.IPv4 => false,
                AddressType.IPv6 => true,
                _ => throw new ProtocolErrorException($"Server replies unexpected ATYP: 0x{buffer[3]:X2}.")
            };

            var headerLength = 4 + (isIPv6 ? IPv6AddressLength : IPv4AddressLength) + PortLength;
            if (buffer.Length <= headerLength)
                ThrowBufferTooSmall(buffer);

            var (address, port) = ReadAddressInfo(isIPv6, buffer.AsSpan(4, headerLength - 4));

            return new UdpReceiveMemory(buffer.AsMemory(headerLength), new IPEndPoint(address, port));
        }

        private async Task PrepareAsync(CancellationToken token) {
            token.ThrowIfCancellationRequested();

            if (_serverAddress != null)
                await TcpClient.ConnectAsync(_serverAddress, _serverPort).ConfigureAwait(false);
            else if (_serverHost != null)
                await TcpClient.ConnectAsync(_serverHost, _serverPort).ConfigureAwait(false);

            _stream ??= TcpClient.GetStream();

            var method = await HandshakeAsync(_credential == null ? MethodsNoAuth : MethodsNoAuthUsernamePassword, token).ConfigureAwait(false);

            if (method == Method.UsernamePassword)
                await AuthenticateAsync(token).ConfigureAwait(false);
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

                await _stream!.WriteAsync(buffer, 0, requestLength, token).ConfigureAwait(false);

                // +-----+--------+
                // | VER | METHOD |
                // +-----+--------+
                // |  1  |   1    |
                // +-----+--------+
                await _stream.ReadRequiredAsync(buffer, 0, 2, token).ConfigureAwait(false);

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

                await _stream!.WriteAsync(buffer, 0, requestLength, token).ConfigureAwait(false);

                // +-----+--------+
                // | VER | STATUS |
                // +-----+--------+
                // |  1  |   1    |
                // +-----+--------+
                await _stream.ReadRequiredAsync(buffer, 0, 2, token).ConfigureAwait(false);

                if (buffer[1] != 0)
                    throw new AuthenticationException($"Authentication failure with status code: 0x{buffer[1]:X}.");

            } finally {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private async Task SendCommandAsync(Command command, string? domain, IPAddress? address, int port, CancellationToken token) {
            const int MaxRequestResponseLength = 1 + 1 + 1 + 1 + DomainLengthByteLength + DomainMaxLength + PortLength;
            var buffer = ArrayPool<byte>.Shared.Rent(MaxRequestResponseLength);

            // +-----+-----+-------+------+----------+----------+
            // | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            // +-----+-----+-------+------+----------+----------+
            // |  1  |  1  | X'00' |  1   | Variable |    2     |
            // +-----+-----+-------+------+----------+----------+
            var addressLength = GetAddressLength(domain, address);
            var requestLength = 1 + 1 + 1 + 1 + (domain != null ? DomainLengthByteLength : 0) + addressLength + PortLength;

            try {
                buffer[0] = Version;
                buffer[1] = (byte)command;
                buffer[2] = 0;
                WriteAddressInfo(addressLength, domain, address, port, buffer, 3);

                await _stream!.WriteAsync(buffer, 0, requestLength, token).ConfigureAwait(false);

                // +-----+-----+-------+------+----------+----------+
                // | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
                // +-----+-----+-------+------+----------+----------+
                // |  1  |  1  | X'00' |  1   | Variable |    2     |
                // +-----+-----+-------+------+----------+----------+
                // 0 length domain in some servers rough implementation
                const int MinResponseLength = 1 + 1 + 1 + 1 + DomainLengthByteLength + 0 + PortLength; 
                const int IPv4ResponseLength = 1 + 1 + 1 + 1 + IPv4AddressLength + PortLength;
                const int IPv6ResponseLength = 1 + 1 + 1 + 1 + IPv6AddressLength + PortLength;

                // At first, try to read the full response.
                var bytesRead = await _stream.ReadAsync(buffer, 0, MaxRequestResponseLength).ConfigureAwait(false);
                // read more until MinResponseLength
                if (bytesRead < MinResponseLength) {
                    await _stream.ReadRequiredAsync(buffer, bytesRead, MinResponseLength - bytesRead, token).ConfigureAwait(false);
                    bytesRead = MinResponseLength;
                }

                // Now, it is guaranteed that at least 7 (MinResponseLength) bytes have been read.
                if ((Reply)buffer[1] != Reply.Successed)
                    throw new ReplyException((Reply)buffer[1]);

                switch ((AddressType)buffer[3]) {
                    case AddressType.IPv4:
                        if (bytesRead < IPv4ResponseLength)
                            await _stream.ReadRequiredAsync(buffer, bytesRead, IPv4ResponseLength - bytesRead, token).ConfigureAwait(false);
                        (_boundAddress, _boundPort) = ReadAddressInfo(isIPv6: false, buffer.AsSpan(4));
                        break;

                    case AddressType.IPv6:
                        if (bytesRead < IPv6ResponseLength)
                            await _stream.ReadRequiredAsync(buffer, bytesRead, IPv6ResponseLength - bytesRead, token).ConfigureAwait(false);
                        (_boundAddress, _boundPort) = ReadAddressInfo(isIPv6: true, buffer.AsSpan(4));
                        break;

                    case AddressType.Domain:
                        if (DomainAddressBehavior == DomainAddressBehavior.UseConnectedAddress) {
                            var domainLength = buffer[4];
                            var domainResponseLength = 1 + 1 + 1 + 1 + DomainLengthByteLength + domainLength + PortLength;
                            if (bytesRead < domainResponseLength)
                                await _stream.ReadRequiredAsync(buffer, bytesRead, domainResponseLength - bytesRead, token)
                                             .ConfigureAwait(false);
                            _boundAddress = RemoteAddress;
                            _boundPort = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(domainResponseLength - PortLength, PortLength));

                        } else { // DomainAddressBehavior.ThrowException
                            throw new ProtocolErrorException($"Server replies unexpected ATYP: 0x{buffer[3]:X2}.");
                        }
                        break;

                    default:
                        throw new ProtocolErrorException($"Server replies unknown ATYP: 0x{buffer[3]:X2}.");
                }

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
                if (!address!.TryWriteBytes(buffer.AsSpan(offset), out _))
                    throw new InvalidOperationException("Address buffer insufficient.");
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
            var address = new IPAddress(buffer[..addressLength]);
#endif

            var port = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(addressLength, 2));

            return (address, port);
        }

        private static void ThrowBufferTooSmall(byte[] buffer) =>
            throw new ProtocolErrorException($"Server replies a packet that was smaller than expected: {BitConverter.ToString(buffer)}");
    }

    /// <summary>
    /// Used to decide whether to ignore the BND.ADDR responded by UDP Associate command.
    /// <para>
    /// In the Internet world, a considerable number of SOCKS5 servers have incorrect UDP Associate implementation. 
    /// </para>
    /// <para>
    /// According to the description of UDP Association in RFC 1928: "In the reply to a UDP ASSOCIATE request, the BND.PORT and BND.ADDR fields indicate the port number/address where the client MUST send UDP request messages to be relayed.", the server should respond its public IP address. If the server has multiple public IP addresses, the server should decide which public IP to respond according to its own strategy. 
    /// </para>
    /// <para>
    /// However, most SOCKS5 servers implementations are very rough. They often use some private addresses as BND.ADDR respond to the client, such as 10.0.0.1, 172.16.1.1, 192.168.1.1 and so on. In this case, the UDP packet sent by the client cannot reach the server at all, unless the client and the server are in the same LAN.
    /// </para>
    /// <para>
    /// Therefore, through this callback, the client can according to the received BND.ADDR to determine whether this address is a private address. If true is returned, the client will send UDP packet to ServerAddress:BND.PORT; If false is returned, it will send UDP packet to BND.ADDR:BND.PORT.
    /// </para>
    /// </summary>
    /// <param name="sender">The <see cref="SocksClient"/> instance which calls the callback.</param>
    /// <param name="address">The BND.ADDR of responded by UDP Associate command.</param>
    /// <returns></returns>
    public delegate Task<bool> ShouldIgnoreBoundAddressCallback(SocksClient sender, IPAddress address);
}
