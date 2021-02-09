using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Socklient {
    static class StreamExtension {
        public static async Task ReadRequiredAsync(this Stream stream, byte[] buffer, int offset, int count, CancellationToken token = default) {
            var bytesReadTotal = 0;
            do {
                token.ThrowIfCancellationRequested();

                var bytesRead = await stream.ReadAsync(buffer, offset + bytesReadTotal, count - bytesReadTotal, token);
                if (bytesRead == 0)
                    throw new EndOfStreamException();

                bytesReadTotal += bytesRead;

            } while (bytesReadTotal < count);
        }
    }

    static class AddressFamilyExtension {
        public static AddressType ToAddressType(this AddressFamily addressFamily) => addressFamily switch {
            AddressFamily.InterNetwork => AddressType.IPv4,
            AddressFamily.InterNetworkV6 => AddressType.IPv6,
            _ => throw new NotImplementedException()
        };
    }
}
