using System;

namespace Taesa.Auth
{
    public class AuthException : Exception
    {
        public AuthException(string message) : base(message)
        {
        }
    }
}