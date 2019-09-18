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
        public AddressType BoundType { get; private set; }
        /// <summary>
        /// BND.ADDR, when ATYP is a Domain
        /// </summary>
        public string BoundDomain { get; private set; }
        /// <summary>
        /// BND.ADDR, when ATYP either IPv4 or IPv6
        /// </summary>
        public IPAddress BoundAddress { get; private set; }
        /// <summary>
        /// BND.PORT
        /// </summary>
        public int BoundPort { get; private set; }

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

        /// <summary>
        /// Get current status of socklient.
        /// </summary>
        public SocksStatus Status { get; private set; } = SocksStatus.Initial;

        public NetworkCredential Credential { get; set; }

        #region Internal Fields
        const byte VERSION = 0x05;
        // Defines in RFC 1929
        const byte AUTHENTICATION_VERSION = 0x01;

        const int IPv4AddressBytes = 4;
        const int IPv6AddressBytes = 16;

        private string _socksServerHost;
        private int _socksServerPort;
        private IPEndPoint _socksServerEndPoint;
        private NetworkStream _stream;
        private Command _socksType;
        private string _udpDestHost;
        private IPAddress _udpDestAddress;
        private int _udpDestPort;
        private bool _disposed = false;
        #endregion

        /// <summary>
        /// Construct a socklient client with specified socks5 server
        /// </summary>
        /// <param name="socksServerHost">Socks5 Server hostname or address</param>
        /// <param name="port">socks5 protocol service port</param>
        public Socklient(string socksServerHost, int port) : this(socksServerHost, port, null) { }

        /// <summary>
        /// Construct a socklient client with specified socks5 server that requires a basic username/password authentication
        /// </summary>
        /// <param name="socksServerHost">Socks5 Server hostname or address</param>
        /// <param name="port">socks5 protocol service port</param>
        /// <param name="credential">a simple credential contains username and password for authentication</param>
        public Socklient(string socksServerHost, int port, NetworkCredential credential) {
            _socksServerHost = socksServerHost;
            _socksServerPort = port;
            Credential = credential;

            if (IPAddress.TryParse(socksServerHost, out var address)) {
                _socksServerEndPoint = new IPEndPoint(address, port);
                TCP = new TcpClient(address.AddressFamily);

            } else {
                TCP = new TcpClient();
            }
        }

        /// <summary>
        /// Construct a socklient client with specified socks5 server
        /// </summary>
        /// <param name="socksServerAddress"></param>
        /// <param name="port"></param>
        public Socklient(IPAddress socksServerAddress, int port) : this(new IPEndPoint(socksServerAddress, port), null) { }

        /// <summary>
        /// Construct a socklient client with specified socks5 server that requires a basic username/password authentication
        /// </summary>
        /// <param name="socksServerAddress"></param>
        /// <param name="port"></param>
        /// <param name="credential"></param>
        public Socklient(IPAddress socksServerAddress, int port, NetworkCredential credential) :
            this(new IPEndPoint(socksServerAddress, port), credential) { }

        /// <summary>
        /// Construct a socklient client with specified socks5 server
        /// </summary>
        /// <param name="socksServerEndPoint"></param>
        public Socklient(IPEndPoint socksServerEndPoint) : this(socksServerEndPoint, null) { }

        /// <summary>
        /// Construct a socklient client with specified socks5 server that requires a basic username/password authentication
        /// </summary>
        /// <param name="socksServerEndPoint"></param>
        /// <param name="credential"></param>
        public Socklient(IPEndPoint socksServerEndPoint, NetworkCredential credential) {
            _socksServerEndPoint = socksServerEndPoint;
            Credential = credential;

            TCP = new TcpClient(socksServerEndPoint.AddressFamily);
        }

        /// <summary>
        /// Send a connect command to socks5 server for TCP relay
        /// </summary>
        /// <param name="destHost">The destination host you want to communicate via socks server</param>
        /// <param name="destPort">The destination port of the host</param>
        public void Connect(string destHost, int destPort) => Connect(destHost, null, destPort);

        /// <summary>
        /// Send a connect command to socks5 server for TCP relay
        /// </summary>
        /// <param name="destAddress">The destination address you want to communicate via socks server</param>
        /// <param name="destPort">The destination port of the host</param>
        public void Connect(IPAddress destAddress, int destPort) => Connect(null, destAddress, destPort);

        /// <summary>
        /// Connect internal implementation
        /// </summary>
        /// <param name="destHost">The destination host you want to communicate via socks server</param>
        /// <param name="destAddress">The destination address you want to communicate via socks server</param>
        /// <param name="destPort">The destination port of the host</param>
        private void Connect(string destHost, IPAddress destAddress, int destPort) {
            if (Status != SocksStatus.Initial)
                throw new InvalidOperationException("This instance already connected.");

            if (_socksServerEndPoint != null)
                TCP.Connect(_socksServerEndPoint);
            else
                TCP.Connect(_socksServerHost, _socksServerPort);

            _stream = TCP.GetStream();

            HandshakeAndAuthentication(Credential);

            SendCommand(Command.Connect, destHost, destAddress, destPort);

            _socksType = Command.Connect;
            Status = SocksStatus.Initialized;
        }

        /// <summary>
        /// Send a connect command to socks5 server for TCP relay as an asynchronous operation
        /// </summary>
        /// <param name="destHost">The destination host you want to communicate via socks server</param>
        /// <param name="destPort">The destination port of the host</param>
        public Task ConnectAsync(string destHost, int destPort) => ConnectAsync(destHost, null, destPort);

        /// <summary>
        /// Send a connect command to socks5 server for TCP relay as an asynchronous operation
        /// </summary>
        /// <param name="destAddress">The destination host you want to communicate via socks server</param>
        /// <param name="destPort">The destination port of the host</param>
        /// <returns></returns>
        public Task ConnectAsync(IPAddress destAddress, int destPort) => ConnectAsync(null, destAddress, destPort);

        /// <summary>
        /// ConnectAsync internal implementation
        /// </summary>
        /// <param name="destHost">The destination host you want to communicate via socks server</param>
        /// <param name="destAddress">The destination address you want to communicate via socks server</param>
        /// <param name="destPort">The destination port of the host</param>
        /// <returns></returns>
        private async Task ConnectAsync(string destHost, IPAddress destAddress, int destPort) {
            if (Status != SocksStatus.Initial)
                throw new InvalidOperationException("This instance already connected.");

            if (_socksServerEndPoint != null)
                await TCP.ConnectAsync(_socksServerEndPoint.Address, _socksServerEndPoint.Port);
            else
                await TCP.ConnectAsync(_socksServerHost, _socksServerPort);

            _stream = TCP.GetStream();

            await HandshakeAndAuthenticationAsync(Credential);

            await SendCommandAsync(Command.Connect, destHost, destAddress, destPort);

            _socksType = Command.Connect;
            Status = SocksStatus.Initialized;
        }

        /// <summary>
        /// Send a udp associate command to socks5 server for UDP relay
        /// </summary>
        /// <param name="destHost">The destination host you want to communicate via socks server</param>
        /// <param name="destPort">The destination port of the host</param>
        /// <param name="srcPort">The local port for communication with socks server</param>
        public void UdpAssociate(string destHost, int destPort, int srcPort = 0) => UdpAssociate(destHost, null, destPort, srcPort);

        /// <summary>
        /// Send a udp associate command to socks5 server for UDP relay
        /// </summary>
        /// <param name="destAddress">The destination address you want to communicate via socks server</param>
        /// <param name="destPort">The destination port of the host</param>
        /// <param name="srcPort">The local port for communication with socks server</param>
        public void UdpAssociate(IPAddress destAddress, int destPort, int srcPort = 0) => UdpAssociate(null, destAddress, destPort, srcPort);

        /// <summary>
        /// UdpAssociate internal implementation
        /// </summary>
        /// <param name="destHost">The destination host you want to communicate via socks server</param>
        /// <param name="destAddress">The destination address you want to communicate via socks server</param>
        /// <param name="destPort">The destination port of the host</param>
        /// <param name="srcPort">The local port for communication with socks server</param>
        private void UdpAssociate(string destHost, IPAddress destAddress, int destPort, int srcPort) {
            if (Status != SocksStatus.Initial)
                throw new InvalidOperationException("This instance already associated.");

            if (_socksServerEndPoint != null)
                TCP.Connect(_socksServerEndPoint);
            else
                TCP.Connect(_socksServerHost, _socksServerPort);

            _stream = TCP.GetStream();

            HandshakeAndAuthentication(Credential);

            _udpDestHost = destHost;
            _udpDestAddress = destAddress;
            _udpDestPort = destPort;

            // create udp client
            UDP = new UdpClient(srcPort, TCP.Client.AddressFamily);
            if (srcPort == 0)
                srcPort = ((IPEndPoint)UDP.Client.LocalEndPoint).Port;

            SendCommand(Command.UdpAssociate, _socksServerHost, _socksServerEndPoint.Address, srcPort);

            // Establishes a default remote host to socks server
            if (BoundType == AddressType.Domain)
                UDP.Connect(BoundDomain, BoundPort);
            else {
                // if BoundAddress is any (0.0.0.0 or ::), change it to socks server
                if (BoundAddress.Equals(IPAddress.Any) || BoundAddress.Equals(IPAddress.IPv6Any))
                    BoundAddress = _socksServerEndPoint?.Address ?? IPAddress.Parse(_socksServerHost);

                UDP.Connect(BoundAddress, BoundPort);
            }

            _socksType = Command.UdpAssociate;
            Status = SocksStatus.Initialized;
        }

        /// <summary>
        /// Send a udp associate command to socks5 server for UDP relay as an asynchronous operation
        /// </summary>
        /// <param name="destHost">The destination host you want to communicate via socks server</param>
        /// <param name="destPort">The destination port of the host</param>
        /// <param name="srcPort">The local port for communication with socks server</param>
        public Task UdpAssociateAsync(string destHost, int destPort, int srcPort = 0) =>
            UdpAssociateAsync(destHost, null, destPort, srcPort);

        /// <summary>
        /// Send a udp associate command to socks5 server for UDP relay as an asynchronous operation
        /// </summary>
        /// <param name="destAddress">The destination address you want to communicate via socks server</param>
        /// <param name="destPort">The destination port of the host</param>
        /// <param name="srcPort">The local port for communication with socks server</param>
        /// <returns></returns>
        public Task UdpAssociateAsync(IPAddress destAddress, int destPort, int srcPort = 0) =>
            UdpAssociateAsync(null, destAddress, destPort, srcPort);

        /// <summary>
        /// UdpAssociateAsync internal implementation
        /// </summary>
        /// <param name="destHost">The destination host you want to communicate via socks server</param>
        /// <param name="destAddress">The destination address you want to communicate via socks server</param>
        /// <param name="destPort">The destination port of the host</param>
        /// <param name="srcPort">The local port for communication with socks server</param>
        /// <returns></returns>
        private async Task UdpAssociateAsync(string destHost, IPAddress destAddress, int destPort, int srcPort) {
            if (Status != SocksStatus.Initial)
                throw new InvalidOperationException("This instance already associated.");

            if (_socksServerEndPoint != null)
                await TCP.ConnectAsync(_socksServerEndPoint.Address, _socksServerEndPoint.Port);
            else
                await TCP.ConnectAsync(_socksServerHost, _socksServerPort);

            _stream = TCP.GetStream();

            await HandshakeAndAuthenticationAsync(Credential);

            _udpDestHost = destHost;
            _udpDestAddress = destAddress;
            _udpDestPort = destPort;

            // create udp client
            UDP = new UdpClient(srcPort, TCP.Client.AddressFamily);
            if (srcPort == 0)
                srcPort = ((IPEndPoint)UDP.Client.LocalEndPoint).Port;

            await SendCommandAsync(Command.UdpAssociate, _socksServerHost, _socksServerEndPoint?.Address, srcPort);

            // Establishes a default remote host to socks server
            if (BoundType == AddressType.Domain)
                UDP.Connect(BoundDomain, BoundPort);
            else {
                // if BoundAddress is any (0.0.0.0 or ::), change it to socks server
                if (BoundAddress.Equals(IPAddress.Any) || BoundAddress.Equals(IPAddress.IPv6Any))
                    BoundAddress = _socksServerEndPoint?.Address ?? IPAddress.Parse(_socksServerHost);

                UDP.Connect(BoundAddress, BoundPort);
            }

            _socksType = Command.UdpAssociate;
            Status = SocksStatus.Initialized;
        }

        /// <summary>
        /// Close and release all connections and local udp ports
        /// </summary>
        public void Close() {
            if (!_disposed) {
                _disposed = true;

                _stream?.Close();
                TCP?.Close();
                UDP?.Close();

                Status = SocksStatus.Closed;
            }
        }

        #region Use for Connect Command        
        // Sync 

        private const string UseGetStreamInstead = "Use GetStream() instead to do the read/write operation.";

        /// <summary>
        /// Sending string data used for TCP relay
        /// </summary>
        /// <param name="str"></param>
        [Obsolete(UseGetStreamInstead)]
        public void Write(string str) {
            Write(Encoding.UTF8.GetBytes(str));
        }

        /// <summary>
        /// Sending bytes data used for TCP relay
        /// </summary>
        /// <param name="data"></param>
        [Obsolete(UseGetStreamInstead)]
        public void Write(byte[] data) {
            CheckSocksStatus(Command.Connect);

            _stream.Write(data, 0, data.Length);
        }

        /// <summary>
        /// Sending bytes data used for TCP relay
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="size"></param>
        [Obsolete(UseGetStreamInstead)]
        public void Write(byte[] buffer, int offset, int size) {
            CheckSocksStatus(Command.Connect);

            _stream.Write(buffer, offset, size);
        }

        /// <summary>
        /// Reading bytes data used for TCP relay
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="size"></param>
        /// <returns></returns>
        [Obsolete(UseGetStreamInstead)]
        public int Read(byte[] buffer, int offset, int size) {
            CheckSocksStatus(Command.Connect);

            return _stream.Read(buffer, offset, size);
        }

        // Async

        /// <summary>
        /// Sending string data used for TCP relay as an asynchronous operation
        /// </summary>
        /// <param name="str"></param>
        [Obsolete(UseGetStreamInstead)]
        public Task WriteAsync(string str) => WriteAsync(Encoding.UTF8.GetBytes(str));

        /// <summary>
        /// Sending bytes data used for TCP relay as an asynchronous operation
        /// </summary>
        /// <param name="data"></param>
        [Obsolete(UseGetStreamInstead)]
        public Task WriteAsync(byte[] data) {
            CheckSocksStatus(Command.Connect);

            return _stream.WriteAsync(data, 0, data.Length);
        }

        /// <summary>
        /// Sending bytes data used for TCP relay as an asynchronous operation
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="size"></param>
        [Obsolete(UseGetStreamInstead)]
        public Task WriteAsync(byte[] buffer, int offset, int size) {
            CheckSocksStatus(Command.Connect);

            return _stream.WriteAsync(buffer, offset, size);
        }

        /// <summary>
        /// Sending bytes data used for TCP relay as an asynchronous operation, and monitors cancellation requests
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="size"></param>
        /// <param name="token"></param>
        [Obsolete(UseGetStreamInstead)]
        public Task WriteAsync(byte[] buffer, int offset, int size, CancellationToken token) {
            CheckSocksStatus(Command.Connect);

            return _stream.WriteAsync(buffer, offset, size, token);
        }

        /// <summary>
        /// Reading bytes data used for TCP relay  as an asynchronous operation
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="size"></param>
        /// <returns></returns>
        [Obsolete(UseGetStreamInstead)]
        public Task<int> ReadAsync(byte[] buffer, int offset, int size) {
            CheckSocksStatus(Command.Connect);

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
        [Obsolete(UseGetStreamInstead)]
        public Task<int> ReadAsync(byte[] buffer, int offset, int size, CancellationToken token) {
            CheckSocksStatus(Command.Connect);

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
        public int Send(string str) => Send(Encoding.UTF8.GetBytes(str));

        /// <summary>
        /// Sending string data to a different host:port that you associate via 'Socklient.UdpAssociate' previously
        /// <para>This method makes "Port-Restricted cone NAT", "Address-Restricted cone NAT" and "Full cone NAT" become possible</para>
        /// </summary>
        /// <param name="str"></param>
        /// <param name="destHost"></param>
        /// <param name="destPort"></param>
        /// <returns></returns>
        public int Send(string str, string destHost, int destPort) => Send(Encoding.UTF8.GetBytes(str), destHost, destPort);

        /// <summary>
        /// Sending user datagram to a different host:port that you associate via 'Socklient.UdpAssociate' previously
        /// <para>This method makes "Port-Restricted cone NAT", "Address-Restricted cone NAT" and "Full cone NAT" become possible</para>
        /// </summary>
        /// <param name="str"></param>
        /// <param name="destAddress"></param>
        /// <param name="destPort"></param>
        /// <returns></returns>
        public int Send(string str, IPAddress destAddress, int destPort) => Send(Encoding.UTF8.GetBytes(str), destAddress, destPort);

        /// <summary>
        /// Sending user datagram used for UDP relay
        /// </summary>
        /// <param name="datagram"></param>
        /// <returns>Sent bytes count</returns>
        public int Send(byte[] datagram) => Send(datagram, 0, datagram.Length, _udpDestHost, _udpDestAddress, _udpDestPort);

        /// <summary>
        /// Sending user datagram used for UDP relay
        /// </summary>
        /// <param name="datagramBuffer"></param>
        /// <param name="offset"></param>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public int Send(byte[] datagramBuffer, int offset, int bytes) =>
            Send(datagramBuffer, offset, bytes, _udpDestHost, _udpDestAddress, _udpDestPort);

        /// <summary>
        /// Sending user datagram to a different host:port that you associate via 'Socklient.UdpAssociate' previously
        /// <para>This method makes "Port-Restricted cone NAT", "Address-Restricted cone NAT" and "Full cone NAT" become possible</para>
        /// </summary>
        /// <param name="datagram"></param>
        /// <param name="destHost"></param>
        /// <param name="destPort"></param>
        /// <returns></returns>
        public int Send(byte[] datagram, string destHost, int destPort) =>
            Send(datagram, 0, datagram.Length, destHost, null, destPort);

        /// <summary>
        /// Sending user datagram to a different host:port that you associate via 'Socklient.UdpAssociate' previously
        /// <para>This method makes "Port-Restricted cone NAT", "Address-Restricted cone NAT" and "Full cone NAT" become possible</para>
        /// </summary>
        /// <param name="datagramBuffer"></param>
        /// <param name="offset"></param>
        /// <param name="bytes"></param>
        /// <param name="destHost"></param>
        /// <param name="destPort"></param>
        /// <returns></returns>
        public int Send(byte[] datagramBuffer, int offset, int bytes, string destHost, int destPort) =>
            Send(datagramBuffer, offset, bytes, destHost, null, destPort);

        /// <summary>
        /// Sending user datagram to a different host:port that you associate via 'Socklient.UdpAssociate' previously
        /// <para>This method makes "Port-Restricted cone NAT", "Address-Restricted cone NAT" and "Full cone NAT" become possible</para>
        /// </summary>
        /// <param name="datagram"></param>
        /// <param name="destAddress"></param>
        /// <param name="destPort"></param>
        /// <returns></returns>
        public int Send(byte[] datagram, IPAddress destAddress, int destPort) =>
            Send(datagram, 0, datagram.Length, null, destAddress, destPort);

        /// <summary>
        /// Sending user datagram to a different host:port that you associate via 'Socklient.UdpAssociate' previously
        /// <para>This method makes "Port-Restricted cone NAT", "Address-Restricted cone NAT" and "Full cone NAT" become possible</para>
        /// </summary>
        /// <param name="datagramBuffer"></param>
        /// <param name="offset"></param>
        /// <param name="bytes"></param>
        /// <param name="destAddress"></param>
        /// <param name="destPort"></param>
        /// <returns></returns>
        public int Send(byte[] datagramBuffer, int offset, int bytes, IPAddress destAddress, int destPort) =>
            Send(datagramBuffer, offset, bytes, null, destAddress, destPort);

        private int Send(byte[] datagramBuffer, int offset, int bytes, string destHost, IPAddress destAddress, int destPort) {
            CheckSocksStatus(Command.UdpAssociate);

            var packedDatagram = PackUdp(destHost, destAddress, destPort, datagramBuffer, offset, bytes);
            var headerLength = packedDatagram.Length - bytes;

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
        public byte[] Receive() => Receive(out _, out _, out _);

        /// <summary>
        /// Receiving datagram with remote host info for UDP relay
        /// </summary>
        /// <param name="remoteHost">the host what you relay via socks5 server</param>
        /// <param name="remoteAddress">the address of host what you relay via socks5 server</param>
        /// <param name="remotePort">the service port of host</param>
        /// <returns></returns>
        public byte[] Receive(out string remoteHost, out IPAddress remoteAddress, out int remotePort) {
            CheckSocksStatus(Command.UdpAssociate);

            return UnpackUdp(UDP.Receive(ref _remoteEndPoint), out remoteHost, out remoteAddress, out remotePort);
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
        /// <param name="destHost"></param>
        /// <param name="destPort"></param>
        /// <returns></returns>
        public Task<int> SendAsync(string str, string destHost, int destPort) =>
            SendAsync(Encoding.UTF8.GetBytes(str), destHost, destPort);

        /// <summary>
        /// As asynchronous operation, sending string data to a different host:port that you associate via 'Socklient.UdpAssociate' previously
        /// <para>It makes "Port-Restricted cone NAT", "Address-Restricted cone NAT" and "Full cone NAT" become possible</para>
        /// </summary>
        /// <param name="str"></param>
        /// <param name="destAddress"></param>
        /// <param name="destPort"></param>
        /// <returns></returns>
        public Task<int> SendAsync(string str, IPAddress destAddress, int destPort) =>
            SendAsync(Encoding.UTF8.GetBytes(str), destAddress, destPort);

        /// <summary>
        /// Sending user datagram used for UDP relay as an asynchronous operation
        /// </summary>
        /// <param name="datagram"></param>
        /// <returns>Sent bytes count</returns>
        public Task<int> SendAsync(byte[] datagram) =>
            SendAsync(datagram, 0, datagram.Length, _udpDestHost, _udpDestAddress, _udpDestPort);

        /// <summary>
        /// Sending user datagram used for UDP relay as an asynchronous operation
        /// </summary>
        /// <param name="datagramBuffer"></param>
        /// <param name="offset"></param>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public Task<int> SendAsync(byte[] datagramBuffer, int offset, int bytes) =>
            SendAsync(datagramBuffer, offset, bytes, _udpDestHost, _udpDestAddress, _udpDestPort);

        /// <summary>
        /// As asynchronous operation, sending user datagram to a different host:port that you associate via 'Socklient.UdpAssociate' previously
        /// <para>It makes "Port-Restricted cone NAT", "Address-Restricted cone NAT" and "Full cone NAT" become possible</para>
        /// </summary>
        /// <param name="datagram"></param>
        /// <param name="destHost"></param>
        /// <param name="destPort"></param>
        /// <returns></returns>
        public Task<int> SendAsync(byte[] datagram, string destHost, int destPort) =>
            SendAsync(datagram, 0, datagram.Length, destHost, null, destPort);

        /// <summary>
        /// As asynchronous operation, sending user datagram to a different host:port that you associate via 'Socklient.UdpAssociate' previously
        /// <para>It makes "Port-Restricted cone NAT", "Address-Restricted cone NAT" and "Full cone NAT" become possible</para>
        /// </summary>
        /// <param name="datagramBuffer"></param>
        /// <param name="offset"></param>
        /// <param name="bytes"></param>
        /// <param name="destHost"></param>
        /// <param name="destPort"></param>
        /// <returns></returns>
        public Task<int> SendAsync(byte[] datagramBuffer, int offset, int bytes, string destHost, int destPort) =>
            SendAsync(datagramBuffer, offset, bytes, destHost, null, destPort);

        /// <summary>
        /// As asynchronous operation, sending user datagram to a different host:port that you associate via 'Socklient.UdpAssociate' previously
        /// <para>It makes "Port-Restricted cone NAT", "Address-Restricted cone NAT" and "Full cone NAT" become possible</para>
        /// </summary>
        /// <param name="datagram"></param>
        /// <param name="destAddress"></param>
        /// <param name="destPort"></param>
        /// <returns></returns>
        public Task<int> SendAsync(byte[] datagram, IPAddress destAddress, int destPort) =>
            SendAsync(datagram, 0, datagram.Length, null, destAddress, destPort);

        /// <summary>
        /// As asynchronous operation, sending user datagram to a different host:port that you associate via 'Socklient.UdpAssociate' previously
        /// <para>It makes "Port-Restricted cone NAT", "Address-Restricted cone NAT" and "Full cone NAT" become possible</para>
        /// </summary>
        /// <param name="datagramBuffer"></param>
        /// <param name="offset"></param>
        /// <param name="bytes"></param>
        /// <param name="destAddress"></param>
        /// <param name="destPort"></param>
        /// <returns></returns>
        public Task<int> SendAsync(byte[] datagramBuffer, int offset, int bytes, IPAddress destAddress, int destPort) =>
            SendAsync(datagramBuffer, offset, bytes, null, destAddress, destPort);

        private async Task<int> SendAsync(byte[] datagramBuffer, int offset, int bytes, string destHost, IPAddress destAddress, int destPort) {
            CheckSocksStatus(Command.UdpAssociate);

            var packedDatagram = PackUdp(destHost, destAddress, destPort, datagramBuffer, offset, bytes);
            var headerLength = packedDatagram.Length - bytes;

            return await UDP.SendAsync(packedDatagram, packedDatagram.Length) - headerLength;
        }

        /// <summary>
        /// Receiving datagram with remote host info for UDP relay as an asynchronous operation
        /// </summary>
        /// <returns></returns>
        public async Task<UdpReceivePacket> ReceiveAsync() {
            CheckSocksStatus(Command.UdpAssociate);

            var result = await UDP.ReceiveAsync();

            var buffer = UnpackUdp(result.Buffer, out var remoteHost, out var remoteAddress, out var remotePort);

            return new UdpReceivePacket(buffer, remoteHost, remoteAddress, remotePort);
        }
        #endregion

        private void HandshakeAndAuthentication(NetworkCredential credential) {
            if (Status == SocksStatus.Initialized)
                throw new InvalidOperationException("Socklient has been initialized.");

            if (Status == SocksStatus.Closed)
                throw new InvalidOperationException("Socklient closed, renew an instance for reuse.");

            var methods = new List<Method> { Method.NoAuthentication };
            if (credential != null)
                methods.Add(Method.UsernamePassword);

            var method = Handshake(methods.ToArray());

            if (method == Method.UsernamePassword)
                Authenticate(credential.UserName, credential.Password);
        }

        private async Task HandshakeAndAuthenticationAsync(NetworkCredential credential) {
            if (Status == SocksStatus.Initialized)
                throw new InvalidOperationException("Socklient has been initialized.");

            if (Status == SocksStatus.Closed)
                throw new InvalidOperationException("Socklient closed, renew an instance for reuse.");

            var methods = new List<Method> { Method.NoAuthentication };
            if (credential != null)
                methods.Add(Method.UsernamePassword);

            var method = await HandshakeAsync(methods.ToArray());

            if (method == Method.UsernamePassword)
                await AuthenticateAsync(credential.UserName, credential.Password);
        }

        private AddressType PackDestinationAddress(string hostName, IPAddress address, out byte[] addressBytes) {
            AddressType addressType;
            if (address != null) {
                addressType = address.AddressFamily == AddressFamily.InterNetworkV6 ? AddressType.IPv6 : AddressType.IPv4;
                addressBytes = address.GetAddressBytes();

            } else {
                var isValid = IPAddress.TryParse(hostName, out address);
                if (isValid) {
                    addressType = address.AddressFamily == AddressFamily.InterNetworkV6 ? AddressType.IPv6 : AddressType.IPv4;
                    addressBytes = address.GetAddressBytes();

                } else {
                    addressType = AddressType.Domain;
                    addressBytes = Encoding.UTF8.GetBytes(hostName);
                }
            }

            return addressType;
        }

        private byte[] PackUdp(string destHost, IPAddress destAddress, int destPort, byte[] payloadBuffer, int offset, int bytes) {
            // Add socks udp associate request header
            // +-----+------+------+----------+----------+----------+
            // | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            // +-----+------+------+----------+----------+----------+
            // |  2  |  1   |  1   | Variable |    2     | Variable |
            // +-----+------+------+----------+----------+----------+

            var type = PackDestinationAddress(destHost, destAddress, out var addressBytes);

            // 1 byte of domain name length followed by 1–255 bytes the domain name if destination address is a domain
            var destAddressLength = addressBytes.Length + (type == AddressType.Domain ? 1 : 0);
            var buffer = new byte[4 + destAddressLength + 2 + bytes];

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
                writer.Write(payloadBuffer, offset, bytes);
            }

            return buffer;
        }

        private byte[] UnpackUdp(byte[] buffer, out string remoteHost, out IPAddress remoteAddress, out int remotePort) {
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
                        remoteAddress = null;

                        addressLength = domainBytesCount;

                    } else {
                        var addressBytesCount = type == AddressType.IPv4 ? IPv4AddressBytes : IPv6AddressBytes;
                        var addressBytes = reader.ReadBytes(addressBytesCount);

                        if (addressBytes.Length != addressBytesCount)
                            throw new ProtocolErrorException($"Server reply an error address, length: {addressBytes.Length}, bytes: {BitConverter.ToString(addressBytes)}");

                        remoteHost = null;
                        remoteAddress = new IPAddress(addressBytes);

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

        private Method Handshake(params Method[] selectionMethods) {
            // Send version and methods
            var sendBuffer = PackHandshake(selectionMethods);
            _stream.Write(sendBuffer, 0, sendBuffer.Length);

            // Receive server selection method 
            var receiveBuffer = new byte[2];
            var numberOfBytesRead = _stream.Read(receiveBuffer, 0, receiveBuffer.Length);

            return UnpackHandshake(receiveBuffer, numberOfBytesRead, selectionMethods);
        }

        private async Task<Method> HandshakeAsync(params Method[] selectionMethods) {
            // Send version and methods
            var sendBuffer = PackHandshake(selectionMethods);
            await _stream.WriteAsync(sendBuffer, 0, sendBuffer.Length);

            // Receive server selection method 
            var receiveBuffer = new byte[2];
            var numberOfBytesRead = await _stream.ReadAsync(receiveBuffer, 0, receiveBuffer.Length);

            return UnpackHandshake(receiveBuffer, numberOfBytesRead, selectionMethods);
        }

        private byte[] PackHandshake(params Method[] selectionMethods) {
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

        private Method UnpackHandshake(byte[] buffer, int numberOfBytesRead, Method[] selectionMethods) {
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

        private void Authenticate(string username, string password) {
            // Send username and password
            var sendBuffer = PackAuthentication(username, password);
            _stream.Write(sendBuffer, 0, sendBuffer.Length);

            // Receive reply
            var receiveBuffer = new byte[2];
            var numberOfBytesRead = _stream.Read(receiveBuffer, 0, receiveBuffer.Length);
            UnpackAuthentication(receiveBuffer, numberOfBytesRead);
        }

        private async Task AuthenticateAsync(string username, string password) {
            // Send username and password
            var sendBuffer = PackAuthentication(username, password);
            await _stream.WriteAsync(sendBuffer, 0, sendBuffer.Length);

            // Receive reply
            var receiveBuffer = new byte[2];
            var numberOfBytesRead = await _stream.ReadAsync(receiveBuffer, 0, receiveBuffer.Length);
            UnpackAuthentication(receiveBuffer, numberOfBytesRead);
        }

        private byte[] PackAuthentication(string username, string password) {
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

            var buffer = new byte[2 + u.Length + 1 + p.Length];

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

        private void UnpackAuthentication(byte[] buffer, int numberOfBytesRead) {
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

        private void SendCommand(Command cmd, string destHostNameOrAddress, IPAddress destAddress, int destPort) {
            // Send command
            var sendBuffer = PackCommand(cmd, destHostNameOrAddress, destAddress, destPort);
            _stream.Write(sendBuffer, 0, sendBuffer.Length);

            // Receive reply
            var receiveBuffer = new byte[512];
            var numberOfBytesRead = _stream.Read(receiveBuffer, 0, receiveBuffer.Length);
            UnpackCommand(receiveBuffer, numberOfBytesRead);
        }

        private async Task SendCommandAsync(Command cmd, string destHostNameOrAddress, IPAddress destAddress, int destPort) {
            // Send command
            var sendBuffer = PackCommand(cmd, destHostNameOrAddress, destAddress, destPort);
            await _stream.WriteAsync(sendBuffer, 0, sendBuffer.Length);

            // Receive reply
            var receiveBuffer = new byte[512];
            var numberOfBytesRead = await _stream.ReadAsync(receiveBuffer, 0, receiveBuffer.Length);
            UnpackCommand(receiveBuffer, numberOfBytesRead);
        }

        private byte[] PackCommand(Command cmd, string destHostNameOrAddress, IPAddress destAddress, int destPort) {
            // +-----+-----+-------+------+----------+----------+
            // | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            // +-----+-----+-------+------+----------+----------+
            // |  1  |  1  | X'00' |  1   | Variable |    2     |
            // +-----+-----+-------+------+----------+----------+

            if (cmd == Command.Bind)
                throw new InvalidOperationException("Unsupport 'Bind' command yet.");

            var type = PackDestinationAddress(destHostNameOrAddress, destAddress, out var addressBytes);

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

        private void UnpackCommand(byte[] buffer, int numberOfBytesRead) {
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
                            var addressBytesCount = BoundType == AddressType.IPv4 ? IPv4AddressBytes : IPv6AddressBytes;
                            var addressBytes = reader.ReadBytes(addressBytesCount);

                            if (addressBytes.Length != addressBytesCount)
                                throw new ProtocolErrorException($"Server reply an error address, length: {addressBytes.Length}, bytes: {BitConverter.ToString(addressBytes)}");

                            BoundAddress = new IPAddress(addressBytes);
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

        private void CheckSocksStatus(Command allowedType) {
            if (_disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            if (_socksType != allowedType)
                throw new InvalidOperationException($"This method only available where socklient under {allowedType} mode");
        }

        private void CheckUdpClient() {
            if (UDP == null)
                throw new InvalidOperationException("This property is available after 'Socklient.UdpAssociate' success.");
        }

        public void Dispose() => Close();
    }

    public class UdpReceivePacket {
        public byte[] Buffer { get; }

        public string RemoteHost { get; }

        public IPAddress RemoteAddress { get; }

        public int RemotePort { get; }

        public UdpReceivePacket(byte[] buffer, string remoteHost, IPAddress remoteAddress, int remotePort) {
            Buffer = buffer;
            RemoteHost = remoteHost;
            RemoteAddress = remoteAddress;
            RemotePort = remotePort;
        }
    }
}
