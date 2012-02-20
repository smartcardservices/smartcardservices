
#include "Configuration.hpp"
//#include "Util.h"
//#include "Singleton.h"
//#include "Context.h"

#include <fstream>
#include <iostream>
#include <algorithm> // remove(), erase()

//namespace Gemalto
//{

/*
*/
Configuration::Configuration( )
{
	m_szConfigurationfilePath = "";
}


/*
*/
void Configuration::load( const std::string& configurationFileName )
{
	m_szConfigurationfilePath = configurationFileName;

	if( false == parse( configurationFileName ) )
	{
		std::string msg = "## ERROR ## Failed opening configuration file (" + configurationFileName + ")";
		std::cout  << msg <<  std::endl;
		throw new std::exception( );
	}
}


/*
*/
void Configuration::getConfigurationFilePath( std::string &result )
{
	result = m_szConfigurationfilePath;
}


///*
//*/
//void Configuration::print( )
//{
//	std::string msg = "print configuration <BEGIN>";
//	Gemalto::Context::getInstance( ).getLog( ).write( msg );
//
//	for( TConfiguration::iterator i = m_configuration.begin( ); i != m_configuration.end( ); i++ )
//	{
//		std::string sectionName = (*i).first;
//		msg = "CurrentSection <" + sectionName + ">";
//		Gemalto::Context::getInstance( ).getLog( ).write( msg );

//		TSection sectionMap = (*i).second;
//		for( TSection::iterator j = sectionMap.begin( ); j != sectionMap.end( ); j++ )
//		{
//			std::string key = (*j).first;
//			std::string value = (*j).second;
//			msg = "    Key <" + key + "> - Value <" + value + ">";
//			Gemalto::Context::getInstance( ).getLog( ).write( msg );
//		}
//	}
//
//	msg = "print configuration <END>";
//	Gemalto::Context::getInstance( ).getLog( ).write( msg );
//}


/*
*/
bool Configuration::checkSection( const std::string& sectionName )
{
	// Find the section into the map of sections
	TConfigurationIterator it = m_configuration.find( sectionName );
	if( m_configuration.end( ) != it )
	{
		return true;
	}
	return false;
}


/*
*/
void Configuration::getValue( const std::string& sectionName, const std::string& keyName, std::string& value )
{
	// Find the section into the map of sections
	TConfigurationIterator it = m_configuration.find( sectionName );
	if( m_configuration.end( ) != it )
	{
		TSection section = it->second;

		// Find the value into the map of entries of the selected section
		TSectionIterator it2 = section.find( keyName );
		if( section.end( ) != it2 )
		{
			value = it2->second;
		}
	}
}


/* Read the whole configuration file
*/
bool Configuration::parse( const std::string& configurationFileName )
{
	//std::string msg = "Configuration file name <" + configurationFileName + ">";
	//std::cout  << " ==== " <<  std::endl;
	//std::cout  << msg <<  std::endl;

	// Open the configuration file
	std::fstream file;
	file.open( configurationFileName.c_str( ), std::ios_base::in );
	if( !file )
	{
		return false;
	}

	// Get the file size
	file.seekg( 0, std::ios_base::end );
	std::streamoff size = file.tellg( );
	file.seekg( 0, std::ios_base::beg );
	//std::cout  << "FILE SIZE <" << size << ">" << std::endl;

	// Read each line of the configuration file
	std::string currentSectionName = "";
	char cStopCharacter = '\n';
	while( !file.eof( ) )
	{
		std::string tmp;
		std::getline( file, tmp, cStopCharacter );
		//std::cout  << "tmp <" << tmp << ">" << std::endl;
		//std::cout  << "tmp.size <" << tmp.size( ) << ">" << std::endl;

		// If the read line is the whole file
		// Then we must restart the parsing changing the ned-line character
		if( size == (int)tmp.size( ) )
		{
			// Reset the read offset to the beginning of the file
			file.seekg( 0, std::ios_base::beg );

			cStopCharacter = '\r';
			tmp = "";
			std::getline( file, tmp, cStopCharacter );
			//std::cout  << "tmp AGAIN <" << tmp << ">" << std::endl;
			//std::cout  << "tmp.size <" << tmp.size( ) << ">" << std::endl;
			if( size == (int)tmp.size( ) )
			{
				std::cout << "## Error - The configuration file is not readable" << std::endl;

				throw new std::exception;
			}
		}

		std::string currentLine = "";
		// Suppress all known end-of-line characters
		suppressAllOccurencesOfThisCharacter( tmp, '\r', currentLine );
		suppressAllOccurencesOfThisCharacter( currentLine, '\n', currentLine );			
		//std::cout  << "currentLine <" << currentLine <<  ">" << std::endl;
		if( currentLine.empty( ) )
		{
			// The current line is empty
			// We must iterate the next current line
			continue;
		}

		// Try to found a comment
		std::string::size_type pos = findComment( currentLine );

		// Try to find a tag before the comment
		std::string::size_type end_pos = 0;
		if( findTag( pos, end_pos, currentLine.substr( 0, pos ) ) )
		{
			// Isolate the potentiel tag
			std::string tag = currentLine.substr( pos, end_pos - pos + 1 );

			// Verify the tag is a real one 
			// (check if the '[' and ']' characters are present)
			if( isSection( tag ) )
			{
				getSectionName( tag, currentSectionName );

				// Populate the section list with the new section
				m_configuration.insert( TConfigurationPair( currentSectionName, TSection( ) ) );

				//std::string msg = "CurrentSection <" + currentSectionName + ">";
				//std::cout  << msg <<  std::endl;
			}
			else if( isKey( tag ) )
			{
				std::string currentKeyName = "";
				getKeyName( tag, currentKeyName );

				std::string currentKeyValue = "";
				getKeyValue( tag, currentKeyValue );

				m_configuration[ currentSectionName ].insert( TEntryPair( currentKeyName, currentKeyValue ) );

				//std::string msg = "    Key <" + currentKeyName + "> - Value <" + currentKeyValue + ">";
				//std::cout  << msg <<  std::endl;
			}
		}
	}

	file.close( );

	//std::cout  << " ==== " <<  std::endl;

	return true;
} 


/* Return the index of the comment into the incomming string.
A comment is marked with with the ';' character
*/
std::string::size_type Configuration::findComment( const std::string& str )
{
	return str.find( ";" );
}


/*
*/
bool Configuration::findTag( std::string::size_type& start, std::string::size_type& end, const std::string& str )
{
	start = str.find_first_not_of( " \t" );
	if( start == std::string::npos )
	{
		return false;
	}

	end = str.find_last_not_of( " \t" );
	if( end == std::string::npos )
	{
		return false;
	}

	if( start >= end )
	{
		return false;
	}

	return true;
}


/*
*/
void Configuration::strip( const std::string& str, std::string &result, const std::string& what )
{
	if( false == str.empty( ) )
	{
		std::string::size_type start = str.find_first_not_of( what );
		std::string::size_type end = str.find_last_not_of( what );

		if( ( std::string::npos != start ) && ( std::string::npos != end ) )
		{
			result.assign( str.substr( start, end - start + 1 ) );
		}
	}
}


/*
*/
bool Configuration::isSection( const std::string& str )
{
	std::string::size_type size = str.size( );

	if( size <= 2 )
	{
		return false;
	}

	if( ( str[ 0 ] == '[' ) && ( str[ size - 1 ] == ']' ) )
	{
		std::string tmp = "";
		strip( str.substr( 1, size - 2 ), tmp );
		if( false == tmp.empty( ) )
		{
			return true;
		}
	}

	return false;
}


/*
*/
bool Configuration::isKey( const std::string& str )
{
	if( str.size() < 2 )
		return false;

	std::string::size_type pos = str.find( "=" );

	if( pos == 0 || pos == std::string::npos )
		return false;

	return true;
}


/*
*/
void Configuration::getKeyName( const std::string& str, std::string &result )
{
	std::string::size_type pos = str.find_first_of( " \t=" );
	if( std::string::npos != pos )
	{
		result.assign( str.substr( 0, pos ) );
	}
}


/*
*/
void Configuration::getKeyValue( const std::string& str, std::string &result )
{
	std::string::size_type start = str.find( "=" );
	std::string::size_type pos = str.find_first_not_of( " \t=", start );

	if( std::string::npos != pos )
	{
		std::string tmp = str.substr( pos );
		result.assign( tmp );
	}
}


/*
*/
void Configuration::getSectionName( const std::string& str, std::string &result )
{
	strip( str.substr( 1, str.size( ) - 2 ), result );
}




/* Suppress all occurences of the targeted character
*/
void Configuration::suppressAllOccurencesOfThisCharacter( const std::string& s, char c, std::string& result )
{ 
	result = s;
	result.erase( std::remove( result.begin( ), result.end( ), c ), result.end( ) ); 
}   


//} //namespace
