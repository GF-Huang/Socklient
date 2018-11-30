/*
 * SOCKS Protocol Version 5: https://tools.ietf.org/html/rfc1928
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SocklientDotNet {
    public class Socklient : IDisposable {
        // +-----+-----+-------+------+----------+----------+
        // | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        // +-----+-----+-------+------+----------+----------+
        // |  1  |  1  | X'00' |  1   | Variable |    2     |
        // +-----+-----+-------+------+----------+----------+
        /// <summary>
        /// ATYP
        /// </summary>
        public AddressType BoundType { get; protected set; }
        /// <summary>
        /// BND.ADDR, when ATYP is a Domain
        /// </summary>
        public string BoundDomain { get; protected set; }
        /// <summary>
        /// BND.ADDR, when ATYP either IPv4 or IPv6
        /// </summary>
        public IPAddress BoundAddress { get; protected set; }
        /// <summary>
        /// BND.PORT
        /// </summary>
        public int BoundPort { get; protected set; }

        /// <summary>
        /// Inner UdpClient timeout setting
        /// </summary>
        [Obsolete("Use property 'UDP' insteads for more fine-grained control")]
        public int UdpSendTimeout {
            get {
                CheckUdpClient();
                return UDP.Client.SendTimeout;
            }
            set {
                CheckUdpClient();
                UDP.Client.SendTimeout = value;
            }
        }
        /// <summary>
        /// Inner UdpClient timeout setting
        /// </summary>
        [Obsolete("Use property 'UDP' insteads for more fine-grained control")]
        public int UdpReceiveTimeout {
            get {
                CheckUdpClient();
                return UDP.Client.ReceiveTimeout;
            }
            set {
                CheckUdpClient();
                UDP.Client.ReceiveTimeout = value;
            }
        }

        /// <summary>
        /// Get underlying TcpClient for more fine-grained control when you are using CONNECT mode
        /// </summary>
        public TcpClient TCP { get; private set; }

        /// <summary>
        /// Get underlying UdpClient for more fine-grained control when you are using UDP-ASSOCIATE mode
        /// </summary>
        public UdpClient UDP { get; private set; }

        #region Internal Fields
        const byte VERSION = 0x05;
        // Defines in RFC 1929
        const byte AUTHENTICATION_VERSION = 0x01;

        string _socksServerHost;
        int _socksServerPort;
        NetworkCredential _credential;
        NetworkStream _stream;
        Status _status = Status.Initial;
        Command _socksType;
        string _udpDestHost;
        int _udpDestPort;
        #endregion

        /// <summary>
        /// Construct a socklient client with specified socks5 server
        /// </summary>
        /// <param name="socks5ServerHost">Socks5 Server hostname or address</param>
        /// <param name="port">socks5 protocol service port</param>
        public Socklient(string socks5ServerHost, int port) : this(socks5ServerHost, port, null) { }

        /// <summary>
        /// Construct a socklient client with specified socks5 server that requires a basic username/password authentication
        /// </summary>
        /// <param name="socks5ServerHost">Socks5 Server hostname or address</param>
        /// <param name="port">socks5 protocol service port</param>
        /// <param name="credential">a simple credential contains username and password for authentication</param>
        public Socklient(string socks5ServerHost, int port, NetworkCredential credential) {
            _socksServerHost = socks5ServerHost;
            _socksServerPort = port;
            _credential = credential;

            TCP = new TcpClient();
        }

        /// <summary>
        /// Send a connect command to socks5 server for TCP relay
        /// </summary>
        /// <param name="destHostNameOrAddress"></param>
        /// <param name="destPort"></param>
        public void Connect(string destHostNameOrAddress, int destPort) {
            TCP.Connect(_socksServerHost, _socksServerPort);
            _stream = TCP.GetStream();

            HandshakeAndAuthentication(_credential);

            SendCommand(Command.Connect, destHostNameOrAddress, destPort);

            _socksType = Command.Connect;
            _status = Status.Initialized;
        }

        /// <summary>
        /// Send a connect command to socks5 server for TCP relay as an asynchronous operation
        /// </summary>
        /// <param name="destHostNameOrAddress"></param>
        /// <param name="destPort"></param>
        public async Task ConnectAsync(string destHostNameOrAddress, int destPort) {
            await TCP.ConnectAsync(_socksServerHost, _socksServerPort);
            _stream = TCP.GetStream();

            await HandshakeAndAuthenticationAsync(_credential);

            await SendCommandAsync(Command.Connect, destHostNameOrAddress, destPort);

            _socksType = Command.Connect;
            _status = Status.Initialized;
        }

        /// <summary>
        /// Send a udp associate command to socks5 server for UDP relay
        /// </summary>
        /// <param name="destHostNameOrAddress"></param>
        /// <param name="destPort"></param>
        /// <param name="srcPort"></param>
        public void UdpAssociate(string destHostNameOrAddress, int destPort, int srcPort = 0) {
            TCP.Connect(_socksServerHost, _socksServerPort);
            _stream = TCP.GetStream();

            HandshakeAndAuthentication(_credential);

            _udpDestHost = destHostNameOrAddress;
            _udpDestPort = destPort;

            SendCommand(Command.UdpAssociate, _socksServerHost, srcPort);

            UDP = new UdpClient(srcPort);
            // Establishes a default remote host to socks server
            UDP.Connect(BoundType == AddressType.Domain ? BoundDomain : BoundAddress.ToString(), BoundPort);

            _socksType = Command.UdpAssociate;
            _status = Status.Initialized;
        }

        /// <summary>
        /// Send a udp associate command to socks5 server for UDP relay as an asynchronous operation
        /// </summary>
        /// <param name="destHostNameOrAddress"></param>
        /// <param name="destPort"></param>
        /// <param name="srcPort"></param>
        public async Task UdpAssociateAsync(string destHostNameOrAddress, int destPort, int srcPort = 0) {
            await TCP.ConnectAsync(_socksServerHost, _socksServerPort);
            _stream = TCP.GetStream();

            await HandshakeAndAuthenticationAsync(_credential);

            _udpDestHost = destHostNameOrAddress;
            _udpDestPort = destPort;

            await SendCommandAsync(Command.UdpAssociate, _socksServerHost, srcPort);

            UDP = new UdpClient(srcPort);
            // Establishes a default remote host to socks server
            UDP.Connect(BoundType == AddressType.Domain ? BoundDomain : BoundAddress.ToString(), BoundPort);

            _socksType = Command.UdpAssociate;
            _status = Status.Initialized;
        }

        /// <summary>
        /// Close and release all connections and local udp ports
        /// </summary>
        public void Close() {
            _stream?.Close();
            TCP?.Close();
            UDP?.Close();

            _stream = null;
            TCP = null;
            UDP = null;

            _status = Status.Closed;
        }

        #region Use for Connect command        
        // Sync 

        /// <summary>
        /// Sending string data used for TCP relay
        /// </summary>
        /// <param name="str"></param>
        public void Write(string str) {
            Write(Encoding.UTF8.GetBytes(str));
        }

        /// <summary>
        /// Sending bytes data used for TCP relay
        /// </summary>
        /// <param name="data"></param>
        public void Write(byte[] data) {
            CheckSocksType(Command.Connect);

            _stream.Write(data, 0, data.Length);
        }

        /// <summary>
        /// Sending bytes data used for TCP relay
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="size"></param>
        public void Write(byte[] buffer, int offset, int size) {
            CheckSocksType(Command.Connect);

            _stream.Write(buffer, offset, size);
        }

        /// <summary>
        /// Reading bytes data used for TCP relay
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="size"></param>
        /// <returns></returns>
        public int Read(byte[] buffer, int offset, int size) {
            CheckSocksType(Command.Connect);

            return _stream.Read(buffer, offset, size);
        }

        // Async

        /// <summary>
        /// Sending string data used for TCP relay as an asynchronous operation
        /// </summary>
        /// <param name="str"></param>
        public Task WriteAsync(string str) => WriteAsync(Encoding.UTF8.GetBytes(str));

        /// <summary>
        /// Sending bytes data used for TCP relay as an asynchronous operation
        /// </summary>
        /// <param name="data"></param>
        public Task WriteAsync(byte[] data) {
            CheckSocksType(Command.Connect);

            return _stream.WriteAsync(data, 0, data.Length);
        }

        /// <summary>
        /// Sending bytes data used for TCP relay as an asynchronous operation
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="size"></param>
        public Task WriteAsync(byte[] buffer, int offset, int size) {
            CheckSocksType(Command.Connect);

            return _stream.WriteAsync(buffer, offset, size);
        }

        /// <summary>
        /// Sending bytes data used for TCP relay as an asynchronous operation, and monitors cancellation requests
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="size"></param>
        /// <param name="token"></param>
        public Task WriteAsync(byte[] buffer, int offset, int size, CancellationToken token) {
            CheckSocksType(Command.Connect);

            return _stream.WriteAsync(buffer, offset, size, token);
        }

        /// <summary>
        /// Reading bytes data used for TCP relay  as an asynchronous operation
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="size"></param>
        /// <returns></returns>
        public Task<int> ReadAsync(byte[] buffer, int offset, int size) {
            CheckSocksType(Command.Connect);

            return _stream.ReadAsync(buffer, offset, size);
        }

        /// <summary>
        /// Reading bytes data used for TCP relay  as an asynchronous operation, and monitors cancellation requests
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="size"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        public Task<int> ReadAsync(byte[] buffer, int offset, int size, CancellationToken token) {
            CheckSocksType(Command.Connect);

            return _stream.ReadAsync(buffer, offset, size, token);
        }
        #endregion

        #region Use for UDP Associate Command
        // Sync

        /// <summary>
        /// Sending string data used for UDP relay
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public int Send(string str) {
            return Send(Encoding.UTF8.GetBytes(str));
        }

        /// <summary>
        /// Sending string data to a different host:port that you associate via 'Socklient.UdpAssociate' previously
        /// <para>It makes "Port-Restricted cone NAT", "Address-Restricted cone NAT" and "Full cone NAT" become possible</para>
        /// </summary>
        /// <param name="str"></param>
        /// <param name="destHostNameOrAddress"></param>
        /// <param name="destPort"></param>
        /// <returns></returns>
        public int Send(string str, string destHostNameOrAddress, int destPort) {
            return Send(Encoding.UTF8.GetBytes(str), destHostNameOrAddress, destPort);
        }

        /// <summary>
        /// Sending user datagram used for UDP relay
        /// </summary>
        /// <param name="datagram"></param>
        /// <returns>Sent bytes count</returns>
        public int Send(byte[] datagram) {
            CheckSocksType(Command.UdpAssociate);

            var packedDatagram = PackUdp(_udpDestHost, _udpDestPort, datagram);
            var headerLength = packedDatagram.Length - datagram.Length;

            return UDP.Send(packedDatagram, packedDatagram.Length) - headerLength;
        }

        /// <summary>
        /// Sending user datagram to a different host:port that you associate via 'Socklient.UdpAssociate' previously
        /// <para>It makes "Port-Restricted cone NAT", "Address-Restricted cone NAT" and "Full cone NAT" become possible</para>
        /// </summary>
        /// <param name="datagram"></param>
        /// <param name="destHostNameOrAddress"></param>
        /// <param name="destPort"></param>
        /// <returns></returns>
        public int Send(byte[] datagram, string destHostNameOrAddress, int destPort) {
            CheckSocksType(Command.UdpAssociate);

            var packedDatagram = PackUdp(destHostNameOrAddress, destPort, datagram);
            var headerLength = packedDatagram.Length - datagram.Length;

            return UDP.Send(packedDatagram, packedDatagram.Length) - headerLength;
        }

        // Typically, we don't care this endpoint.
        // Works for an ugly API design of UdpClient.Receive(ref System.Net.IPEndPoint remoteEP), 
        // use 'out' instead of 'ref' is easier to use.
        // See its source: https://referencesource.microsoft.com/#System/net/System/Net/Sockets/UDPClient.cs,695
        private IPEndPoint _remoteEndPoint = new IPEndPoint(IPAddress.Loopback, 0);

        /// <summary>
        /// Receiving datagram for UDP relay
        /// </summary>
        /// <returns></returns>
        public byte[] Receive() => Receive(out _, out _);

        /// <summary>
        /// Receiving datagram with remote host info for UDP relay
        /// </summary>
        /// <param name="remoteHost">the host what you relay via socks5 server</param>
        /// <param name="remotePort">the service port of host</param>
        /// <returns></returns>
        public byte[] Receive(out string remoteHost, out int remotePort) {
            CheckSocksType(Command.UdpAssociate);

            return UnpackUdp(UDP.Receive(ref _remoteEndPoint), out remoteHost, out remotePort);
        }

        // Async

        /// <summary>
        /// Sending string data used for UDP relay as an asynchronous operation
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public Task<int> SendAsync(string str) => SendAsync(Encoding.UTF8.GetBytes(str));

        /// <summary>
        /// As asynchronous operation, sending string data to a different host:port that you associate via 'Socklient.UdpAssociate' previously
        /// <para>It makes "Port-Restricted cone NAT", "Address-Restricted cone NAT" and "Full cone NAT" become possible</para>
        /// </summary>
        /// <param name="str"></param>
        /// <param name="destHostNameOrAddress"></param>
        /// <param name="destPort"></param>
        /// <returns></returns>
        public Task<int> SendAsync(string str, string destHostNameOrAddress, int destPort) => 
            SendAsync(Encoding.UTF8.GetBytes(str), destHostNameOrAddress, destPort);

        /// <summary>
        /// Sending user datagram used for UDP relay as an asynchronous operation
        /// </summary>
        /// <param name="datagram"></param>
        /// <returns>Sent bytes count</returns>
        public async Task<int> SendAsync(byte[] datagram) {
            CheckSocksType(Command.UdpAssociate);

            var packedDatagram = PackUdp(_udpDestHost, _udpDestPort, datagram);
            var headerLength = packedDatagram.Length - datagram.Length;

            return await UDP.SendAsync(packedDatagram, packedDatagram.Length) - headerLength;
        }

        /// <summary>
        /// As asynchronous operation, sending user datagram to a different host:port that you associate via 'Socklient.UdpAssociate' previously
        /// <para>It makes "Port-Restricted cone NAT", "Address-Restricted cone NAT" and "Full cone NAT" become possible</para>
        /// </summary>
        /// <param name="datagram"></param>
        /// <param name="destHostNameOrAddress"></param>
        /// <param name="destPort"></param>
        /// <returns></returns>
        public async Task<int> SendAsync(byte[] datagram, string destHostNameOrAddress, int destPort) {
            CheckSocksType(Command.UdpAssociate);

            var packedDatagram = PackUdp(destHostNameOrAddress, destPort, datagram);
            var headerLength = packedDatagram.Length - datagram.Length;

            return await UDP.SendAsync(packedDatagram, packedDatagram.Length) - headerLength;
        }

        /// <summary>
        /// Receiving datagram with remote host info for UDP relay as an asynchronous operation
        /// </summary>
        /// <returns></returns>
        public async Task<UdpReceivePacket> ReceiveAsync() {
            CheckSocksType(Command.UdpAssociate);

            var result = await UDP.ReceiveAsync();

            var buffer = UnpackUdp(result.Buffer, out var remoteHost, out var remotePort);

            return new UdpReceivePacket(buffer, remoteHost, remotePort);
        }
        #endregion

        protected void HandshakeAndAuthentication(NetworkCredential credential) {
            if (_status == Status.Initialized)
                throw new InvalidOperationException("Socklient has been initialized.");

            if (_status == Status.Closed)
                throw new InvalidOperationException("Socklient closed, renew an instance for reuse.");

            var methods = new List<Method> { Method.NoAuthentication };
            if (credential != null)
                methods.Add(Method.UsernamePassword);

            var method = Handshake(methods.ToArray());

            if (method == Method.UsernamePassword)
                Authenticate(credential.UserName, credential.Password);
        }

        protected async Task HandshakeAndAuthenticationAsync(NetworkCredential credential) {
            if (_status == Status.Initialized)
                throw new InvalidOperationException("Socklient has been initialized.");

            if (_status == Status.Closed)
                throw new InvalidOperationException("Socklient closed, renew an instance for reuse.");

            var methods = new List<Method> { Method.NoAuthentication };
            if (credential != null)
                methods.Add(Method.UsernamePassword);

            var method = await HandshakeAsync(methods.ToArray());

            if (method == Method.UsernamePassword)
                await AuthenticateAsync(credential.UserName, credential.Password);
        }

        protected AddressType PackDestinationAddress(string hostNameOrAddress, out byte[] addressBytes) {
            var isValid = IPAddress.TryParse(hostNameOrAddress, out var address);

            AddressType addressType;
            if (isValid) {
                addressType = address.AddressFamily == AddressFamily.InterNetworkV6 ? AddressType.IPv6 : AddressType.IPv4;
                addressBytes = address.GetAddressBytes();

            } else {
                addressType = AddressType.Domain;
                addressBytes = Encoding.UTF8.GetBytes(hostNameOrAddress);
            }

            return addressType;
        }

        protected byte[] PackUdp(string destHostNameOrAddress, int destPort, byte[] payload) {
            // Add socks udp associate request header
            // +-----+------+------+----------+----------+----------+
            // | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            // +-----+------+------+----------+----------+----------+
            // |  2  |  1   |  1   | Variable |    2     | Variable |
            // +-----+------+------+----------+----------+----------+

            var type = PackDestinationAddress(destHostNameOrAddress, out var addressBytes);

            // 1 byte of domain name length followed by 1–255 bytes the domain name if destination address is a domain
            var destAddressLength = addressBytes.Length + (type == AddressType.Domain ? 1 : 0);
            var buffer = new byte[4 + destAddressLength + 2 + payload.Length];

            using (var stream = new MemoryStream(buffer))
            using (var writer = new BinaryWriter(stream)) {
                writer.Write(ushort.MinValue);
                writer.Write(byte.MinValue);
                writer.Write((byte)type);

                switch (type) {
                    case AddressType.IPv4:
                    case AddressType.IPv6:
                        writer.Write(addressBytes);
                        break;
                    case AddressType.Domain:
                        writer.Write((byte)addressBytes.Length);
                        writer.Write(addressBytes);
                        break;
                    default:
                        throw new InvalidOperationException($"Unsupported type: {type}.");
                }

                writer.Write(IPAddress.HostToNetworkOrder((short)destPort));
                writer.Write(payload);
            }

            return buffer;
        }

        protected byte[] UnpackUdp(byte[] buffer, out string remoteHost, out int remotePort) {
            // Remove socks udp associate reply header
            // +-----+------+------+----------+----------+----------+
            // | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            // +-----+------+------+----------+----------+----------+
            // |  2  |  1   |  1   | Variable |    2     | Variable |
            // +-----+------+------+----------+----------+----------+

            using (var stream = new MemoryStream(buffer))
            using (var reader = new BinaryReader(stream)) {
                try {
                    // ignore RSV and FRAG fields
                    reader.ReadBytes(3);

                    var type = (AddressType)reader.ReadByte();
                    var addressLength = 0;

                    if (type == AddressType.Domain) {
                        var domainBytesCount = reader.ReadByte();
                        var domainBytes = reader.ReadBytes(domainBytesCount);

                        if (domainBytes.Length != domainBytesCount)
                            throw new ProtocolErrorException($"Server reply a error domain, length: {domainBytes.Length}, bytes: {BitConverter.ToString(domainBytes)}, domain: {Encoding.UTF8.GetString(domainBytes)}");

                        remoteHost = Encoding.UTF8.GetString(domainBytes);

                        addressLength = domainBytesCount;

                    } else {
                        var addressBytesCount = type == AddressType.IPv4 ? 4 : 16;
                        var addressBytes = reader.ReadBytes(addressBytesCount);

                        if (addressBytes.Length != addressBytesCount)
                            throw new ProtocolErrorException($"Server reply an error address, length: {addressBytes.Length}, bytes: {BitConverter.ToString(addressBytes)}");

                        remoteHost = new IPAddress(addressBytes).ToString();

                        addressLength = addressBytesCount;
                    }

                    remotePort = (ushort)IPAddress.NetworkToHostOrder(reader.ReadInt16());

                    var payloadLength = buffer.Length - 4 - addressLength - 2;

                    return reader.ReadBytes(payloadLength);

                } catch (EndOfStreamException) {
                    throw new ProtocolErrorException($"Server respond unknown message: {BitConverter.ToString(buffer)}.");
                }
            }
        }

        protected Method Handshake(params Method[] selectionMethods) {
            // Send version and methods
            var sendBuffer = PackHandshake(selectionMethods);
            _stream.Write(sendBuffer, 0, sendBuffer.Length);

            // Receive server selection method 
            var receiveBuffer = new byte[2];
            var numberOfBytesRead = _stream.Read(receiveBuffer, 0, receiveBuffer.Length);

            return UnpackHandshake(receiveBuffer, numberOfBytesRead, selectionMethods);
        }

        protected async Task<Method> HandshakeAsync(params Method[] selectionMethods) {
            // Send version and methods
            var sendBuffer = PackHandshake(selectionMethods);
            await _stream.WriteAsync(sendBuffer, 0, sendBuffer.Length);

            // Receive server selection method 
            var receiveBuffer = new byte[2];
            var numberOfBytesRead = await _stream.ReadAsync(receiveBuffer, 0, receiveBuffer.Length);

            return UnpackHandshake(receiveBuffer, numberOfBytesRead, selectionMethods);
        }

        protected byte[] PackHandshake(params Method[] selectionMethods) {
            // +-----+----------+----------+
            // | VER | NMETHODS | METHODS  |
            // +-----+----------+----------+
            // |  1  |    1     | 1 to 255 |
            // +-----+----------+----------+

            if (selectionMethods.Length > 255)
                throw new InvalidOperationException("Param 'selectionMethods'.Length can not greater than 255.");

            var buffer = new byte[2 + selectionMethods.Length];

            using (var stream = new MemoryStream(buffer))
            using (var writer = new BinaryWriter(stream)) {
                writer.Write(VERSION);
                writer.Write((byte)selectionMethods.Length);
                writer.Write(Array.ConvertAll(selectionMethods, m => (byte)m));
            }

            return buffer;
        }

        protected Method UnpackHandshake(byte[] buffer, int numberOfBytesRead, Method[] selectionMethods) {
            // +-----+--------+
            // | VER | METHOD |
            // +-----+--------+
            // |  1  |   1    |
            // +-----+--------+

            if (numberOfBytesRead < 2)
                throw new ProtocolErrorException($"Server respond unknown message: {BitConverter.ToString(buffer, 0, numberOfBytesRead)}.");

            var serverVersion = buffer[0];
            if (serverVersion != VERSION)
                throw new ProtocolErrorException($"Server version isn't 5: 0x{serverVersion:X2}.");

            var serverMethod = (Method)buffer[1];
            if (!Enum.IsDefined(typeof(Method), serverMethod))
                throw new ProtocolErrorException($"Server respond a unknown method: 0x{(byte)serverMethod:X2}.");

            if (!selectionMethods.Contains(serverMethod))
                throw new MethodUnsupportedException($"Server respond a method({serverMethod}:0x{(byte)serverMethod:X2}) that is not in 'selectionMethods'.", serverMethod);

            return serverMethod;
        }

        protected void Authenticate(string username, string password) {
            // Send username and password
            var sendBuffer = PackAuthentication(username, password);
            _stream.Write(sendBuffer, 0, sendBuffer.Length);

            // Receive reply
            var receiveBuffer = new byte[2];
            var numberOfBytesRead = _stream.Read(receiveBuffer, 0, receiveBuffer.Length);
            UnpackAuthentication(receiveBuffer, numberOfBytesRead);
        }

        protected async Task AuthenticateAsync(string username, string password) {
            // Send username and password
            var sendBuffer = PackAuthentication(username, password);
            await _stream.WriteAsync(sendBuffer, 0, sendBuffer.Length);

            // Receive reply
            var receiveBuffer = new byte[2];
            var numberOfBytesRead = await _stream.ReadAsync(receiveBuffer, 0, receiveBuffer.Length);
            UnpackAuthentication(receiveBuffer, numberOfBytesRead);
        }

        protected byte[] PackAuthentication(string username, string password) {
            // +-----+------+----------+------+----------+
            // | VER | ULEN |  UNAME   | PLEN |  PASSWD  |
            // +-----+------+----------+------+----------+
            // |  1  |  1   | 1 to 255 |  1   | 1 to 255 |
            // +-----+------+----------+------+----------+

            var u = Encoding.UTF8.GetBytes(username);
            if (u.Length > 255)
                throw new InvalidOperationException("The length of param 'username' that convert to bytes can not greater than 255.");

            var p = Encoding.UTF8.GetBytes(password);
            if (p.Length > 255)
                throw new InvalidOperationException("The length of param 'password' that convert to bytes can not greater than 255.");

            var buffer = new byte[2 + u.Length + 1 + u.Length];

            using (var stream = new MemoryStream(buffer))
            using (var writer = new BinaryWriter(stream)) {
                writer.Write(AUTHENTICATION_VERSION);
                writer.Write((byte)u.Length);
                writer.Write(u);
                writer.Write((byte)p.Length);
                writer.Write(p);
            }

            return buffer;
        }

        protected void UnpackAuthentication(byte[] buffer, int numberOfBytesRead) {
            // +-----+--------+
            // | VER | STATUS |
            // +-----+--------+
            // |  1  |   1    |
            // +-----+--------+

            if (numberOfBytesRead < 2)
                throw new ProtocolErrorException($"Server respond unknown message: {BitConverter.ToString(buffer, 0, numberOfBytesRead)}.");

            var status = buffer[1];
            if (status != 0x00)
                throw new AuthenticationFailureException($"Authentication fail because server respond status code: {status}.", status);
        }

        protected void SendCommand(Command cmd, string destHostNameOrAddress, int destPort) {
            // Send command
            var sendBuffer = PackCommand(cmd, destHostNameOrAddress, destPort);
            _stream.Write(sendBuffer, 0, sendBuffer.Length);

            // Receive reply
            var receiveBuffer = new byte[512];
            var numberOfBytesRead = _stream.Read(receiveBuffer, 0, receiveBuffer.Length);
            UnpackCommand(receiveBuffer, numberOfBytesRead, destHostNameOrAddress);
        }

        protected async Task SendCommandAsync(Command cmd, string destHostNameOrAddress, int destPort) {
            // Send command
            var sendBuffer = PackCommand(cmd, destHostNameOrAddress, destPort);
            await _stream.WriteAsync(sendBuffer, 0, sendBuffer.Length);

            // Receive reply
            var receiveBuffer = new byte[512];
            var numberOfBytesRead = await _stream.ReadAsync(receiveBuffer, 0, receiveBuffer.Length);
            UnpackCommand(receiveBuffer, numberOfBytesRead, destHostNameOrAddress);
        }

        protected byte[] PackCommand(Command cmd, string destHostNameOrAddress, int destPort) {
            // +-----+-----+-------+------+----------+----------+
            // | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            // +-----+-----+-------+------+----------+----------+
            // |  1  |  1  | X'00' |  1   | Variable |    2     |
            // +-----+-----+-------+------+----------+----------+

            if (cmd == Command.Bind)
                throw new InvalidOperationException("Unsupport 'Bind' command yet.");

            var type = PackDestinationAddress(destHostNameOrAddress, out var addressBytes);

            // 1 byte of domain name length followed by 1–255 bytes the domain name if destination address is a domain
            var destAddressLength = addressBytes.Length + (type == AddressType.Domain ? 1 : 0);
            var buffer = new byte[4 + destAddressLength + 2];

            using (var stream = new MemoryStream(buffer))
            using (var writer = new BinaryWriter(stream)) {
                writer.Write(VERSION);
                writer.Write((byte)cmd);
                writer.Write(byte.MinValue);
                writer.Write((byte)type);

                switch (type) {
                    case AddressType.IPv4:
                    case AddressType.IPv6:
                        writer.Write(addressBytes);
                        break;
                    case AddressType.Domain:
                        writer.Write((byte)addressBytes.Length);
                        writer.Write(addressBytes);
                        break;
                    default:
                        throw new InvalidOperationException($"Unsupported type: {type}.");
                }
                writer.Write(IPAddress.HostToNetworkOrder((short)destPort));
            }

            return buffer;
        }

        protected void UnpackCommand(byte[] buffer, int numberOfBytesRead, string destHostNameOrAddress) {
            // +-----+-----+-------+------+----------+----------+
            // | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            // +-----+-----+-------+------+----------+----------+
            // |  1  |  1  | X'00' |  1   | Variable |    2     |
            // +-----+-----+-------+------+----------+----------+            

            using (var stream = new MemoryStream(buffer, 0, numberOfBytesRead))
            using (var reader = new BinaryReader(stream)) {
                try {
                    var version = reader.ReadByte();
                    if (version != VERSION)
                        throw new ProtocolErrorException($"Server version isn't 5: 0x{version:X2}.");

                    var rep = (Reply)reader.ReadByte();
                    if (rep != Reply.Successed)
                        throw new CommandException($"Command failed, server reply: {rep}.", rep);

                    // ignore RSV field
                    reader.ReadByte();

                    BoundType = (AddressType)reader.ReadByte();

                    switch (BoundType) {
                        case AddressType.IPv4:
                        case AddressType.IPv6: {
                            var addressBytesCount = BoundType == AddressType.IPv4 ? 4 : 16;
                            var addressBytes = reader.ReadBytes(addressBytesCount);

                            if (addressBytes.Length != addressBytesCount)
                                throw new ProtocolErrorException($"Server reply an error address, length: {addressBytes.Length}, bytes: {BitConverter.ToString(addressBytes)}");

                            BoundAddress = new IPAddress(addressBytes);
                            if (_socksType == Command.UdpAssociate && (BoundAddress.Equals(IPAddress.Any) || BoundAddress.Equals(IPAddress.IPv6Any)))
                                BoundAddress = IPAddress.Parse(destHostNameOrAddress);

                            break;
                        }

                        case AddressType.Domain: {
                            var numberOfDomainBytes = reader.ReadByte();
                            var domainBytes = reader.ReadBytes(numberOfDomainBytes);

                            if (domainBytes.Length != numberOfDomainBytes)
                                throw new ProtocolErrorException($"Server reply a error domain, length: {domainBytes.Length}, bytes: {BitConverter.ToString(domainBytes)}, domain: {Encoding.UTF8.GetString(domainBytes)}");

                            BoundDomain = Encoding.UTF8.GetString(domainBytes);

                            break;
                        }
                        default:
                            throw new ProtocolErrorException($"Server reply an unsupported address type: {BoundType}.");
                    }

                    BoundPort = (ushort)IPAddress.NetworkToHostOrder(reader.ReadInt16());

                } catch (EndOfStreamException) {
                    throw new ProtocolErrorException($"Server respond unknown message: {BitConverter.ToString(buffer, 0, numberOfBytesRead)}.");
                }
            }
        }

        protected void CheckSocksType(Command allowedType) {
            if (_socksType != allowedType)
                throw new InvalidOperationException($"This method only available where socklient under {allowedType} mode");
        }

        protected void CheckUdpClient() {
            if (UDP == null)
                throw new InvalidOperationException("This property is available after 'Socklient.UdpAssociate' success.");
        }

        enum Status {
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

        public void Dispose() => Close();
    }

    public readonly struct UdpReceivePacket {
        public byte[] Buffer { get; }

        public string RemoteHost { get; }

        public int RemotePort { get; }

        public UdpReceivePacket(byte[] buffer, string remoteHost, int remotePort) {
            Buffer = buffer;
            RemoteHost = remoteHost;
            RemotePort = remotePort;
        }
    }
}
