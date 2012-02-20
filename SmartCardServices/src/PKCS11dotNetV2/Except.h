/*
*  PKCS#11 library for .Net smart cards
*  Copyright (C) 2007-2009 Gemalto <support@gemalto.com>
*
*  This library is free software; you can redistribute it and/or
*  modify it under the terms of the GNU Lesser General Public
*  License as published by the Free Software Foundation; either
*  version 2.1 of the License, or (at your option) any later version.
*
*  This library is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
*  Lesser General Public License for more details.
*
*  You should have received a copy of the GNU Lesser General Public
*  License along with this library; if not, write to the Free Software
*  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*
*/

#ifndef _include_marshaller_except_h
#define _include_marshaller_except_h

#include <stdexcept>

    MARSHALLER_NS_BEGIN

    // .NET specific exception classes
class Exception  : public std::runtime_error{

public:
    explicit Exception(std::string msg): std::runtime_error(msg) { }
    const char *what() const throw(){
        return std::runtime_error::what();
    }
};

class SystemException : public Exception{

public:
    explicit SystemException(std::string msg) : Exception(msg) { }
    explicit SystemException(const char *msg) : Exception(NULL != msg ? msg : "") { }
};

class ArgumentException : public Exception{

public:
    explicit ArgumentException(std::string msg) : Exception(msg) { }
    explicit ArgumentException();
    explicit ArgumentException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class ArgumentNullException : public Exception{

public:
    explicit ArgumentNullException(std::string msg) : Exception(msg) { }
    explicit ArgumentNullException();
    explicit ArgumentNullException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class ArgumentOutOfRangeException : public Exception{

public:
    explicit ArgumentOutOfRangeException(std::string msg) : Exception(msg) { }
    explicit ArgumentOutOfRangeException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class IndexOutOfRangeException : public Exception{

public:
    explicit IndexOutOfRangeException(std::string  msg) : Exception(msg) { }
    explicit IndexOutOfRangeException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class InvalidCastException : public Exception{

public:
    explicit InvalidCastException(std::string  msg) : Exception(msg) { }
    explicit InvalidCastException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class InvalidOperationException : public Exception{

public:
    explicit InvalidOperationException(std::string msg) : Exception(msg) { }
    explicit InvalidOperationException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class NotImplementedException : public Exception{

public:
    explicit NotImplementedException(std::string msg) : Exception(msg) { }
    explicit NotImplementedException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class NotSupportedException : public Exception{

public:
    explicit NotSupportedException(std::string msg) : Exception(msg) { }
    explicit NotSupportedException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class NullReferenceException : public Exception{

public:
    explicit NullReferenceException(std::string msg) : Exception(msg) { }
    explicit NullReferenceException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class OutOfMemoryException : public Exception{

public:
    explicit OutOfMemoryException(std::string msg) : Exception(msg) { }
    explicit OutOfMemoryException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class UnauthorizedAccessException : public Exception{

public:
    explicit UnauthorizedAccessException(std::string msg) : Exception(msg) { }
    explicit UnauthorizedAccessException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class ObjectDisposedException : public Exception{

public:
    explicit ObjectDisposedException(std::string msg) : Exception(msg) { }
    explicit ObjectDisposedException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class ApplicationException : public Exception{

public:
    explicit ApplicationException(std::string msg) : Exception(msg) { }
    explicit ApplicationException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class ArithmeticException : public Exception{

public:
    explicit ArithmeticException(std::string msg) : Exception(msg) { }
    explicit ArithmeticException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class ArrayTypeMismatchException : public Exception{

public:
    explicit ArrayTypeMismatchException(std::string msg) : Exception(msg) { }
    explicit ArrayTypeMismatchException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class BadImageFormatException : public Exception{

public:
    explicit BadImageFormatException(std::string msg) : Exception(msg) { }
    explicit BadImageFormatException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class CryptographicException : public Exception{

public:
    explicit CryptographicException(std::string msg) : Exception(msg) { }
    explicit CryptographicException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class DirectoryNotFoundException : public Exception{

public:
    explicit DirectoryNotFoundException(std::string msg) : Exception(msg) { }
    explicit DirectoryNotFoundException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class DivideByZeroException : public Exception{

public:
    explicit DivideByZeroException(std::string msg) : Exception(msg) { }
    explicit DivideByZeroException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class FileNotFoundException : public Exception{

public:
    explicit FileNotFoundException(std::string msg) : Exception(msg) { }
    explicit FileNotFoundException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class FormatException : public Exception{

public:
    explicit FormatException(std::string msg) : Exception(msg) { }
    explicit FormatException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class IOException : public Exception{

public:
    explicit IOException(std::string msg) : Exception(msg) { }
    explicit IOException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class RankException : public Exception{

public:
    explicit RankException(std::string msg) : Exception(msg) { }
    explicit RankException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};


/*
*/
class RemotingException : public Exception {

private:

    long m_ResultCode;

public:

    explicit RemotingException( const std::string& msg ) : Exception( msg ) { m_ResultCode = 0; }

    explicit RemotingException( const char *msg ) : Exception( NULL != msg ? msg : "" ) { m_ResultCode = 0; }
    
    explicit RemotingException( const std::string& msg, const long& a_resultCode ) : Exception( msg ) { m_ResultCode = a_resultCode; }
    
    explicit RemotingException( const char *msg, const long& a_resultCode ) : Exception( NULL != msg ? msg : "" ){ m_ResultCode = a_resultCode; }

    explicit RemotingException( const long& a_resultCode ) : Exception( "" ) { m_ResultCode = a_resultCode; }
    
    long getResultCode( void ) { return m_ResultCode; }
};


class StackOverflowException : public Exception{

public:
    explicit StackOverflowException(std::string msg) : Exception(msg) { }
    explicit StackOverflowException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class TypeLoadException : public Exception{

public:
    explicit TypeLoadException(std::string msg) : Exception(msg) { }
    explicit TypeLoadException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class MemberAccessException : public Exception{

public:
    explicit MemberAccessException(std::string msg) : Exception(msg) { }
    explicit MemberAccessException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class MissingFieldException : public Exception{

public:
    explicit MissingFieldException(std::string msg) : Exception(msg) { }
    explicit MissingFieldException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class MissingMemberException : public Exception{

public:
    explicit MissingMemberException(std::string msg) : Exception(msg) { }
    explicit MissingMemberException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class MissingMethodException : public Exception{

public:
    explicit MissingMethodException(std::string msg) : Exception(msg) { }
    explicit MissingMethodException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class OverflowException : public Exception{

public:
    explicit OverflowException(std::string msg) : Exception(msg) { }
    explicit OverflowException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class SecurityException : public Exception{

public:
    explicit SecurityException(std::string msg) : Exception(msg) { }
    explicit SecurityException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class VerificationException : public Exception{

public:
    explicit VerificationException(std::string msg) : Exception(msg) { }
    explicit VerificationException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

class SerializationException : public Exception{

public:
    explicit SerializationException(std::string msg) : Exception(msg) { }
    explicit SerializationException(const char *msg) : Exception(NULL != msg ? msg : "") { }

};

MARSHALLER_NS_END

#endif

