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

#ifndef _include_cardcache_h
#define _include_cardcache_h


#include "cardmoduleservice.h"


#include <map>
#include <string>
#include <vector>

class CardCache
{
public:
   struct Container
   {
      u1Array exchPublicExponent;
      u1Array exchModulus;
      u1Array signPublicExponent;
      u1Array signModulus;
   };

   CardCache(CardModuleService *  mscm);
   void WriteFile(std::string const & path, u1Array const & data);
   const u1Array & ReadFile(std::string const & path);
   void ClearFile(std::string const & path);

   const Container & ReadContainer( int const &ctrIndex ) const;
   void ClearContainer(int const &ctrIndex);

   const std::vector<std::string> & FileList(std::string const & dir);
   void ClearFileList(std::string const & dir);

   void ClearAll();

private:
   void ManageGC( void );
   CardModuleService * _mscm;
   mutable std::map<std::string, u1Array> _fileCache;
   mutable std::map<int, Container> _contCache;
   mutable std::map<std::string, vector<string> > _fileList;

};

#endif // _include_cardcache_h
