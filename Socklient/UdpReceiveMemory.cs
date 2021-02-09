using System;
using System.Buffers;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace Socklient {
    /// <summary>
    /// Presents SOCKS5 server UDP replied result information from a call to the <see cref="SocksClient.ReceiveAsync"/> method.
    /// </summary>
    public readonly struct UdpReceiveMemory : IEquatable<UdpReceiveMemory> {
        /// <summary>
        /// Gets the <see cref="ReadOnlyMemory{T}"/> with the data received in the UDP packet.
        /// </summary>
        public ReadOnlyMemory<byte> Memory { get; }

        /// <summary>
        /// Gets the remote endpoint from which the UDP packet was received.
        /// </summary>
        public IPEndPoint RemoteEndPoint { get; }

        internal UdpReceiveMemory(ReadOnlyMemory<byte> memory, IPEndPoint remoteEndPoint) {
            Memory = memory;
            RemoteEndPoint = remoteEndPoint;
        }

#pragma warning disable CS1591 // 缺少对公共可见类型或成员的 XML 注释
        public override bool Equals(object obj) => obj is UdpReceiveMemory other && Equals(other);

        public bool Equals(UdpReceiveMemory other) => Memory.Equals(other) && RemoteEndPoint.Equals(other.RemoteEndPoint);

        public override int GetHashCode() => Memory.GetHashCode() ^ RemoteEndPoint.GetHashCode();

        public static bool operator ==(UdpReceiveMemory left, UdpReceiveMemory right) => left.Equals(right);

        public static bool operator !=(UdpReceiveMemory left, UdpReceiveMemory right) => !(left == right);
#pragma warning restore CS1591 // 缺少对公共可见类型或成员的 XML 注释
    }
}
