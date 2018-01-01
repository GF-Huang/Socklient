using System;
using System.Collections.Generic;
using System.Text;

namespace SocklientDotNet {
    public class ProtocolErrorException : Exception {
        public ProtocolErrorException() { }
        public ProtocolErrorException(string message) : base(message) { }
        public ProtocolErrorException(string message, Exception inner) : base(message, inner) { }
    }


    public class MethodUnsupportedException : Exception {
        public Method ServerReplyMethod { get; private set; }
        public MethodUnsupportedException(Method serverReplyMethod) { ServerReplyMethod = serverReplyMethod; }
        public MethodUnsupportedException(string message, Method serverReplyMethod) : base(message) { ServerReplyMethod = serverReplyMethod; }
        public MethodUnsupportedException(string message, Method serverReplyMethod, Exception inner) : base(message, inner) { ServerReplyMethod = serverReplyMethod; }
    }


    public class AuthenticationFailureException : Exception {
        public byte StatusCode { get; private set; }
        public AuthenticationFailureException(byte statusCode) { StatusCode = statusCode; }
        public AuthenticationFailureException(string message, byte statusCode) : base(message) { StatusCode = statusCode; }
        public AuthenticationFailureException(string message, byte statusCode, Exception inner) : base(message, inner) { StatusCode = statusCode; }
    }


    public class CommandException : Exception {
        public Reply Reply { get; private set; }
        public CommandException(Reply reply) { Reply = reply; }
        public CommandException(string message, Reply reply) : base(message) { Reply = reply; }
        public CommandException(string message, Reply reply, Exception inner) : base(message, inner) { Reply = reply; }
    }
}
