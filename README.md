Socklient
=========
A SOCKS5 Client written in C# that implements RFC 1928 &amp; 1929.

Features
========
Support TCP (Connect) & UDP Associate

NuGet
=====
https://www.nuget.org/packages/Socklient

Example
=======

### TCP
```cs
using Socklient;


using var client = new SocksClient(IPAddress.Parse("xxx.xxx.xxx.xxx") /* or some server hostname or domain */, 
                                   1080 /* or other ports */);
await client.ConnectAsync("somewebsite.com", 80 /*or 443 or other ports*/);
var stream = client.GetStream();
// Read and Write on this stream
await stream.ReadAsync(...)
await stream.WriteAsync(...)
```

### UDP
```cs
using Socklient;


using var client = new SocksClient(IPAddress.Parse("xxx.xxx.xxx.xxx") /* or some server hostname or domain */, 
                                   1080 /* or other ports */);
// Usually, all personal users are NAT, so there is no way to determine the public IP and port they will use before sending.
// In this case, the client MUST use a port number and address of all zeros.
// More details read the this method comments or go to https://tools.ietf.org/html/rfc1928 then search "zeros" keyword.
await client.UdpAssociateAsync(IPAddress.Any, 0); 
// Then Send and Receive on the client instance
await client.SendAsync(...);
UdpReceiveMemory result = await client.ReceiveAsync();
IPEndPoint remote = result.RemoteEndPoint; // the remote 
ReadOnlyMemory<byte> buffer = result.Memory; // the buffer contains the received data from remote
```
