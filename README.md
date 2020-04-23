Socklient
=========
A Socks5 Client written in C# that implements RFC 1928 &amp; 1929.

Features
========
Support TCP (Connect) & UDP Associate

NuGet
=====
https://www.nuget.org/packages/Socklient

Example
=======

TCP Relay:
```csharp
// Find a SOCKS5 server by yourself, google search is a easy way.
var SOCKS5ServerHostNameOrAddress = "xxx.xxx.xxx.xxx"; // or a hostname
var serverPort = 0; // assign service port you found of SOCKS5 server

var targetHost = "httpbin.org"; // a target host you want to visit
var targetPort = 80; // target port 

// Tcp Example
try {
    // init with SOCKS5 server information
    var socklient = new Socklient(SOCKS5ServerHostNameOrAddress, serverPort);
    // you can pass a NetworkCredential contains username/password if socks server need a basic authencation
    //var socklient = new Socklient(SOCKS5ServerHostNameOrAddress, serverPort, new System.Net.NetworkCredential("user", "pwd"));

    // tell socks server connect to target server
    socklient.Connect(targetHost, targetPort);

    Console.WriteLine($"TCP: Supported, {socklient.BoundType} {(socklient.BoundType == AddressType.Domain ? socklient.BoundDomain : socklient.BoundAddress.ToString())}:{socklient.BoundPort}");

    using var stream = socklient.GetStream();

    // write a http request or others you want
    var requestData = Encoding.UTF8.GetBytes("GET http://httpbin.org/ip HTTP/1.1\r\nHost: httpbin.org\r\n\r\n");
    stream.Write(requestData, 0, requestData.Length);

    // receive reply data
    var buffer = new byte[1024];
    stream.Read(buffer, 0, buffer.Length);

    Console.WriteLine($"Receive: {Environment.NewLine}{Encoding.UTF8.GetString(buffer)}");

    // close connection
    socklient.Close();

} catch (Exception e) {
    Console.WriteLine($"TCP: {e.Message}");
}
```

UDP Relay:
```csharp
// Udp Example
try {
    // you can pass a NetworkCredential contains username/password if socks server need a basic authencation
    // var socklient = new Socklient(SOCKS5ServerHostNameOrAddress, serverPort, new System.Net.NetworkCredential("user", "pwd"));

    using var socklient = new Socklient(SOCKS5ServerHostNameOrAddress, serverPort);

    // find some udp service by yourself, for example: UDP echo, DNS, etc...
    targetHost = "anyhost.provide.udpservice";
    targetPort = 0;

    // If the client is not in possesion of the information at the time of UDP Associate(for example, all personal users are NAT, there is no way to determine the public IP and port they will use before sending), the client MUST use a port number and address of all zeros.
    socklient.UdpAssociate(IPAddress.Any, 0);
    // set timeout for receive
    socklient.UDP.Client.ReceiveTimeout = 5000;

    Console.WriteLine($"UDP: Supported, {socklient.BoundType} {(socklient.BoundType == AddressType.Domain ? socklient.BoundDomain : socklient.BoundAddress.ToString())}:{socklient.BoundPort}");

    // send data via SOCKS5 server
    socklient.Send(new byte[] { 1, 2, 3, 4 }, targetHost, targetPort);

    // receive data and remote host information that sent back data to SOCKS5 server
    var received = BitConverter.ToString(socklient.Receive(out var remoteHost, out var remoteAddress, out var remotePort));
    Console.WriteLine($"Receive from {remoteHost}:{remotePort} {received}");

} catch (Exception e) {
    Console.WriteLine($"UDP: {e.Message}");
}
```
