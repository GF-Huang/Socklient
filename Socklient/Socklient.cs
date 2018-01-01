using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SocklientDotNet {
    public class Socklient : IDisposable {
        public AddressType BoundType { get; protected set; }
        public string BoundDomain { get; protected set; }
        public IPAddress BoundAddress { get; protected set; }
        public int BoundPort { get; protected set; }

        #region Internal Fields
        static readonly byte VERSION = 0x05;
        // Defines in RFC 1929
        static readonly byte AUTHENTICATION_VERSION = 0x01;

        string _socksServerHost;
        NetworkCredential _credential;
        TcpClient _tcpClient;
        NetworkStream _stream;
        Status _status = Status.Initial;
        Command _socksType;

        UdpClient _udpClient;
        string _udpDestHost;
        int _udpDestPort;
        #endregion

        public Socklient(string socks5ServerHost, int port) : this(socks5ServerHost, port, null) { }

        public Socklient(string socks5ServerHost, int port, NetworkCredential credential) {
            _socksServerHost = socks5ServerHost;
            _credential = credential;
            // Connect to server
            _tcpClient = new TcpClient(socks5ServerHost, port);
            _stream = _tcpClient.GetStream();
        }

        public void Connect(string destHost, int destPort) {
            HandshakeAndAuthentication(_credential);

            SendCommand(Command.Connect, GetAddressType(destHost), destHost, destPort);

            _socksType = Command.Connect;
        }
        
        public void UdpAssociate(string destHost, int destPort, int srcPort = 0) {
            HandshakeAndAuthentication(_credential);

            _udpDestHost = destHost;
            _udpDestPort = destPort;

            SendCommand(Command.UdpAssociate, GetAddressType(_socksServerHost), _socksServerHost, srcPort);

            _udpClient = new UdpClient(srcPort);
            // Establishes a default remote host to socks server
            _udpClient.Connect(BoundType == AddressType.Domain ? BoundDomain : BoundAddress.ToString(), BoundPort);

            _socksType = Command.UdpAssociate;
        }

        public void Close() {
            if (_stream != null)
                _stream.Close();
            if (_tcpClient != null)
                _tcpClient.Close();
            if (_udpClient != null)
                _udpClient.Close();

            _stream = null;
            _tcpClient = null;
            _udpClient = null;

            _status = Status.Closed;
        }

        #region Use for Connect command        
        public void Write(string str) {
            Write(Encoding.UTF8.GetBytes(str));
        }

        public void Write(byte[] data) {
            CheckSocksType(Command.Connect);

            _stream.Write(data, 0, data.Length);
        }

        public void Write(byte[] buffer, int offset, int size) {
            CheckSocksType(Command.Connect);

            _stream.Write(buffer, offset, size);
        }

        public int Read(byte[] buffer, int offset, int size) {
            CheckSocksType(Command.Connect);

            return _stream.Read(buffer, offset, size);
        }
        #endregion


        #region Use for UDP Associate Command
        public int Send(string str) {
            return Send(Encoding.UTF8.GetBytes(str));
        }

        public int Send(byte[] datagram) {
            CheckSocksType(Command.UdpAssociate);

            var packedDatagram = PackUdp(_udpDestHost, _udpDestPort, datagram);
            return _udpClient.Send(packedDatagram, packedDatagram.Length);
        }

        // Works for an ugly API design of UdpClient.Receive(ref System.Net.IPEndPoint remoteEP), use 'out' instead of 'ref' is easier to use.
        // See its source: https://referencesource.microsoft.com/#System/net/System/Net/Sockets/UDPClient.cs,695
        private IPEndPoint _remoteEndPoint = new IPEndPoint(IPAddress.Loopback, 0);

        public byte[] Receive() {
            return Receive(out _, out _);
        }

        public byte[] Receive(out string remoteHost, out int remotePort) {
            CheckSocksType(Command.UdpAssociate);
            
            return UnpackUdp(_udpClient.Receive(ref _remoteEndPoint), out remoteHost, out remotePort);
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

        protected AddressType GetAddressType(string hostNameOrAddress) {
            var isValid = IPAddress.TryParse(hostNameOrAddress, out var address);

            AddressType addressType;
            if (isValid)
                addressType = address.AddressFamily == AddressFamily.InterNetworkV6 ? AddressType.IPv6 : AddressType.IPv4;
            else
                addressType = AddressType.Domain;

            return addressType;
        }

        protected byte[] PackUdp(string destHostOrAddress, int destPort, byte[] payload) {
            // Add socks udp associate request header
            // +-----+------+------+----------+----------+----------+
            // | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            // +-----+------+------+----------+----------+----------+
            // |  2  |  1   |  1   | Variable |    2     | Variable |
            // +-----+------+------+----------+----------+----------+
            var buffer = new List<byte>();

            var type = GetAddressType(destHostOrAddress);

            buffer.AddRange(new byte[] { 0x00, 0x00 }); // RSV
            buffer.Add(0x00); // FRAG
            buffer.Add((byte)type); // ATYP
            // DST.ADDR
            switch (type) {
                case AddressType.IPv4:
                case AddressType.IPv6:
                    buffer.AddRange(IPAddress.Parse(destHostOrAddress).GetAddressBytes());
                    break;
                case AddressType.Domain:
                    var hostNameBytes = Encoding.UTF8.GetBytes(destHostOrAddress);
                    buffer.Add((byte)hostNameBytes.Length);
                    buffer.AddRange(hostNameBytes);
                    break;
                default:
                    throw new InvalidOperationException($"[SendCommand] Unsupported type: {type}.");
            }
            // DST.PORT
            buffer.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)destPort)));
            // DATA
            buffer.AddRange(payload);

            return buffer.ToArray();
        }

        protected byte[] UnpackUdp(byte[] buffer, out string remoteHost, out int remotePort) {
            // Remove socks udp associate reply header
            // +-----+------+------+----------+----------+----------+
            // | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            // +-----+------+------+----------+----------+----------+
            // |  2  |  1   |  1   | Variable |    2     | Variable |
            // +-----+------+------+----------+----------+----------+
            var headerLength = 4;

            var addressType = (AddressType)buffer[3];

            if (addressType == AddressType.Domain) {
                var numberOfDomainBytes = buffer[4];
                remoteHost = Encoding.UTF8.GetString(buffer, 5, numberOfDomainBytes);

                headerLength += numberOfDomainBytes + 1;

            } else {
                var addressBytes = new byte[addressType == AddressType.IPv4 ? 4 : 16];
                Buffer.BlockCopy(buffer, 4, addressBytes, 0, addressBytes.Length);
                remoteHost = new IPAddress(addressBytes).ToString();

                headerLength += addressBytes.Length;
            }

            remotePort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer, headerLength));

            headerLength += 2;

            var originDatagram = new byte[buffer.Length - headerLength];
            Buffer.BlockCopy(buffer, headerLength, originDatagram, 0, originDatagram.Length);

            return originDatagram;
        }

        protected Method Handshake(params Method[] selectionMethods) {
            if (selectionMethods.Length > 255)
                throw new InvalidOperationException("[Handshake] Param 'selectionMethods'.Length can not greater than 255.");

            // Send version and methods
            // +-----+----------+----------+
            // | VER | NMETHODS | METHODS  |
            // +-----+----------+----------+
            // |  1  |    1     | 1 to 255 |
            // +-----+----------+----------+
            var sendBuffer = new List<byte>();
            sendBuffer.Add(VERSION);
            sendBuffer.Add((byte)selectionMethods.Length);
            sendBuffer.AddRange(selectionMethods.Select(m => (byte)m));

            _stream.Write(sendBuffer.ToArray(), 0, sendBuffer.Count);


            // Receive server selection method 
            // +-----+--------+
            // | VER | METHOD |
            // +-----+--------+
            // |  1  |   1    |
            // +-----+--------+
            var receiveBuffer = new byte[2];
            var numberOfBytesRead = _stream.Read(receiveBuffer, 0, receiveBuffer.Length);
            if (numberOfBytesRead < 2)
                throw new ProtocolErrorException($"[Handshake] Server respond unknown message: {BitConverter.ToString(receiveBuffer, 0, numberOfBytesRead)}.");

            // Check result
            var serverVersion = receiveBuffer[0];
            if (serverVersion != VERSION)
                throw new ProtocolErrorException($"[Handshake] Server version isn't 5: 0x{serverVersion:X2}.");

            var serverMethod = (Method)receiveBuffer[1];
            if (!Enum.IsDefined(typeof(Method), serverMethod))
                throw new ProtocolErrorException($"[Handshake] Server respond a unknown method: 0x{(byte)serverMethod:X2}.");

            if (!selectionMethods.Contains(serverMethod))
                throw new MethodUnsupportedException($"[Handshake] Server respond a method({serverMethod}:0x{(byte)serverMethod:X2}) that is not in 'selectionMethods'.", serverMethod);

            return serverMethod;
        }

        protected void Authenticate(string username, string password) {
            // Send username and password
            // +-----+------+----------+------+----------+
            // | VER | ULEN |  UNAME   | PLEN |  PASSWD  |
            // +-----+------+----------+------+----------+
            // |  1  |  1   | 1 to 255 |  1   | 1 to 255 |
            // +-----+------+----------+------+----------+
            var u = Encoding.UTF8.GetBytes(username);
            if (u.Length > 255)
                throw new InvalidOperationException("[Authenticate] The length of param 'username' that convert to bytes can not greater than 255.");

            var p = Encoding.UTF8.GetBytes(password);
            if (p.Length > 255)
                throw new InvalidOperationException("[Authenticate] The length of param 'password' that convert to bytes can not greater than 255.");

            var sendBuffer = new List<byte>();
            sendBuffer.Add(AUTHENTICATION_VERSION);
            sendBuffer.Add((byte)u.Length);
            sendBuffer.AddRange(u);
            sendBuffer.Add((byte)p.Length);
            sendBuffer.AddRange(p);

            _stream.Write(sendBuffer.ToArray(), 0, sendBuffer.Count);


            // Receive reply
            // +-----+--------+
            // | VER | STATUS |
            // +-----+--------+
            // |  1  |   1    |
            // +-----+--------+
            var receiveBuffer = new byte[2];
            var numberOfBytesRead = _stream.Read(receiveBuffer, 0, receiveBuffer.Length);
            if (numberOfBytesRead < 2)
                throw new ProtocolErrorException($"[Authenticate] Server respond unknown message: {BitConverter.ToString(receiveBuffer, 0, numberOfBytesRead)}.");

            var status = receiveBuffer[1];
            if (status != 0x00)
                throw new AuthenticationFailureException($"[Authenticate] Authentication fail because server respond status code: {status}.", status);
        }

        protected void SendCommand(Command cmd, AddressType type, string destAddress, int destPort) {
            if (cmd == Command.Bind)
                throw new InvalidOperationException("Unsupport 'Bind' command yet.");

            // Send command
            // +-----+-----+-------+------+----------+----------+
            // | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            // +-----+-----+-------+------+----------+----------+
            // |  1  |  1  | X'00' |  1   | Variable |    2     |
            // +-----+-----+-------+------+----------+----------+
            var sendBuffer = new List<byte>();
            sendBuffer.Add(VERSION);
            sendBuffer.Add((byte)cmd);
            sendBuffer.Add(0x00);
            sendBuffer.Add((byte)type);
            switch (type) {
                case AddressType.IPv4:
                case AddressType.IPv6:
                    sendBuffer.AddRange(IPAddress.Parse(destAddress).GetAddressBytes());
                    break;
                case AddressType.Domain:
                    var hostNameBytes = Encoding.UTF8.GetBytes(destAddress);
                    sendBuffer.Add((byte)hostNameBytes.Length);
                    sendBuffer.AddRange(hostNameBytes);
                    break;
                default:
                    throw new InvalidOperationException($"[SendCommand] Unsupported type: {type}.");
            }
            sendBuffer.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)destPort)));
            _stream.Write(sendBuffer.ToArray(), 0, sendBuffer.Count);


            // Receive reply
            // +-----+-----+-------+------+----------+----------+
            // | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            // +-----+-----+-------+------+----------+----------+
            // |  1  |  1  | X'00' |  1   | Variable |    2     |
            // +-----+-----+-------+------+----------+----------+
            const int numberOfFieldsBytesWithoutAddrPort = 4;
            const int numberOfFieldsBytesWithoutAddr = 4 + 2;

            var receiveBuffer = new byte[512];
            var numberOfBytesRead = _stream.Read(receiveBuffer, 0, receiveBuffer.Length);

            if (numberOfBytesRead == 0)
                throw new ProtocolErrorException($"[SendCommand] Server respond empty message.");

            if (numberOfBytesRead < 2)
                throw new ProtocolErrorException($"[SendCommand] Server respond unknown message: {BitConverter.ToString(receiveBuffer, 0, numberOfBytesRead)}.");

            if (receiveBuffer[0] != VERSION)
                throw new ProtocolErrorException($"[SendCommand] Server version isn't 5: 0x{receiveBuffer[0]:X2}.");

            var rep = (Reply)receiveBuffer[1];
            if (rep != Reply.Successed)
                throw new CommandException($"[SendCommand] Command failed, server reply: {rep}.", rep);

            var replyType = (AddressType)receiveBuffer[3];
            BoundType = replyType;

            switch (replyType) {
                case AddressType.IPv4:
                case AddressType.IPv6: {
                        var numberOfAddressBytes = replyType == AddressType.IPv4 ? 4 : 16;

                        if (numberOfBytesRead < numberOfAddressBytes + numberOfFieldsBytesWithoutAddr)
                            throw new ProtocolErrorException($"[SendCommand] Server respond unknown message: {BitConverter.ToString(receiveBuffer, 0, numberOfBytesRead)}.");

                        var addressBytes = new byte[numberOfAddressBytes];
                        Buffer.BlockCopy(receiveBuffer, 4, addressBytes, 0, addressBytes.Length);

                        BoundAddress = new IPAddress(addressBytes);
                        if (_socksType == Command.UdpAssociate && (BoundAddress.Equals(IPAddress.Any) || BoundAddress.Equals(IPAddress.IPv6Any)))
                            BoundAddress = IPAddress.Parse(destAddress);                        
                    }
                    break;
                case AddressType.Domain: {
                        if (numberOfBytesRead < numberOfFieldsBytesWithoutAddrPort + 1)
                            throw new ProtocolErrorException($"[SendCommand] Server respond unknown message: {BitConverter.ToString(receiveBuffer, 0, numberOfBytesRead)}.");

                        var numberOfDomainBytes = receiveBuffer[4];
                        if (numberOfBytesRead < numberOfFieldsBytesWithoutAddr + numberOfDomainBytes + 1)
                            throw new ProtocolErrorException($"[SendCommand] Server respond unknown message: {BitConverter.ToString(receiveBuffer, 0, numberOfBytesRead)}.");

                        BoundDomain = Encoding.UTF8.GetString(receiveBuffer, 5, numberOfDomainBytes);
                    }
                    break;
                default:
                    throw new ProtocolErrorException($"[SendCommand] Server reply an unsupported address type: {replyType}.");
            }

            BoundPort = (ushort)IPAddress.NetworkToHostOrder(BitConverter.ToInt16(receiveBuffer, numberOfBytesRead - 2));
        }

        protected void CheckSocksType(Command allowedType) {
            if (_socksType != allowedType)
                throw new InvalidOperationException($"This method only available where socklient under {allowedType} mode");
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

        public void Dispose() {
            Close();
        }
    }
}
