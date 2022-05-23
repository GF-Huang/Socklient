using System;
using System.Collections.Generic;
using System.Text;

#pragma warning disable CS1591 // 缺少对公共可见类型或成员的 XML 注释

namespace Socklient {
    /// <summary>
    /// The exception that is thrown when the SOCKS5 server replies unexpected response.
    /// </summary>
    [Serializable]
    public class ProtocolErrorException : Exception {
        public ProtocolErrorException() { }
        public ProtocolErrorException(string message) : base(message) { }
        public ProtocolErrorException(string message, Exception inner) : base(message, inner) { }
        protected ProtocolErrorException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }

    /// <summary>
    /// The exception that is thrown when authentication failed.
    /// </summary>
    [Serializable]
    public class AuthenticationException : Exception {
        public AuthenticationException() { }
        public AuthenticationException(string message) : base(message) { }
        public AuthenticationException(string message, Exception inner) : base(message, inner) { }
        protected AuthenticationException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }

    /// <summary>
    /// The exception that is thrown when the REP field not equals to <see cref="Reply.Successed"/>(0x00).
    /// </summary>
    [Serializable]
    public class ReplyException : Exception {
        public Reply Reply { get; }

        public ReplyException(Reply reply) : base($"Server reply error: {reply}.") => Reply = reply;
        public ReplyException(Reply reply, string message) : base(message) => Reply = reply;
        public ReplyException(Reply reply, string message, Exception inner) : base(message, inner) => Reply = reply;
        protected ReplyException(
          System.Runtime.Serialization.SerializationInfo info,
          System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
    }
}

#pragma warning restore CS1591 // 缺少对公共可见类型或成员的 XML 注释