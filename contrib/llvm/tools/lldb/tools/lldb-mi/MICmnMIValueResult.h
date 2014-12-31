//===-- MICmnMIResult.h -----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

//++
// File:		MICmnMIResult.h
//
// Overview:	CMICmnMIValueResult interface.
//
// Environment:	Compilers:	Visual C++ 12.
//							gcc (Ubuntu/Linaro 4.8.1-10ubuntu9) 4.8.1
//				Libraries:	See MIReadmetxt. 
//
// Copyright:	None.
//--

#pragma once

// In-house headers:
#include "MICmnMIValue.h"

//++ ============================================================================
// Details:	MI common code MI Result class. Part of the CMICmnMIValueResultRecord
//			set of objects.
//			The syntax is as follows:
//			result-record ==>  [ token ] "^" result-class ( "," result )* nl 
//			token = any sequence of digits
//			* = 0 to many
//			nl = CR | CR_LF
//			result-class ==> "done" | "running" | "connected" | "error" | "exit" 
//			result ==> variable "=" value
//			value ==> const | tuple | list  
//			const ==> c-string (7 bit iso c string content)
//			tuple ==>  "{}" | "{" result ( "," result )* "}"  
//			list ==>  "[]" | "[" value ( "," value )* "]" | "[" result ( "," result )* "]"  
//			More information see: 
//			http://ftp.gnu.org/old-gnu/Manuals/gdb-5.1.1/html_chapter/gdb_22.html
// Gotchas:	None.
// Authors:	Illya Rudkin 24/02/2014.
// Changes:	None.
//--
class CMICmnMIValueResult : public CMICmnMIValue
{
// Methods:
public:
	/* ctor */	CMICmnMIValueResult( void );
	/* ctor */	CMICmnMIValueResult( const CMIUtilString & vVariable, const CMICmnMIValue & vValue );
	/* ctor */	CMICmnMIValueResult( const CMIUtilString & vVariable, const CMICmnMIValue & vValue, const bool vbUseSpacing );
	//
	bool	Add( const CMIUtilString & vVariable, const CMICmnMIValue & vValue );

// Overridden:
public:
	// From CMICmnBase
	/* dtor */ virtual ~CMICmnMIValueResult( void );

// Methods:
private:
	bool	BuildResult( void );
	bool	BuildResult( const CMIUtilString & vVariable, const CMICmnMIValue & vValue );

// Attributes:
private:
	static const CMIUtilString	ms_constStrEqual;
	//
	CMIUtilString	m_strPartVariable;
	CMICmnMIValue	m_partMIValue;
	bool			m_bEmptyConstruction;	// True = *this object used constructor with no parameters, false = constructor with parameters
	bool			m_bUseSpacing;			// True = put space seperators into the string, false = no spaces used
};
