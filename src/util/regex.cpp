#include "util/regex.h"

#pragma once
#pragma pack(push, 8)

#include <comdef.h>
#include <atlbase.h>

//
// Forward references and typedefs
//

struct __declspec(uuid("3f4daca7-160d-11d2-a8e9-00104b365c9f"))
/* LIBID */ __VBScript_RegExp_10;
struct __declspec(uuid("3f4daca0-160d-11d2-a8e9-00104b365c9f"))
/* dual interface */ IRegExp;
struct __declspec(uuid("3f4daca1-160d-11d2-a8e9-00104b365c9f"))
/* dual interface */ IMatch;
struct __declspec(uuid("3f4daca2-160d-11d2-a8e9-00104b365c9f"))
/* dual interface */ IMatchCollection;
struct /* coclass */ RegExp;
struct /* coclass */ Match;
struct /* coclass */ MatchCollection;

//
// Smart pointer typedef declarations
//

_COM_SMARTPTR_TYPEDEF(IRegExp, __uuidof(IRegExp));
_COM_SMARTPTR_TYPEDEF(IMatch, __uuidof(IMatch));
_COM_SMARTPTR_TYPEDEF(IMatchCollection, __uuidof(IMatchCollection));

//
// Type library items
//

struct __declspec(uuid("3f4daca0-160d-11d2-a8e9-00104b365c9f"))
IRegExp : IDispatch
{
    //
    // Property data
    //

    __declspec(property(get=GetPattern,put=PutPattern))
    _bstr_t Pattern;
    __declspec(property(get=GetIgnoreCase,put=PutIgnoreCase))
    VARIANT_BOOL IgnoreCase;
    __declspec(property(get=GetGlobal,put=PutGlobal))
    VARIANT_BOOL Global;

    //
    // Wrapper methods for error-handling
    //

    _bstr_t GetPattern ( );
    void PutPattern (
        _bstr_t pPattern );
    VARIANT_BOOL GetIgnoreCase ( );
    void PutIgnoreCase (
        VARIANT_BOOL pIgnoreCase );
    VARIANT_BOOL GetGlobal ( );
    void PutGlobal (
        VARIANT_BOOL pGlobal );
    IDispatchPtr Execute (
        _bstr_t sourceString );
    VARIANT_BOOL Test (
        _bstr_t sourceString );
    _bstr_t Replace (
        _bstr_t sourceString,
        _bstr_t replaceString );

    //
    // Raw methods provided by interface
    //

      virtual HRESULT __stdcall get_Pattern (
        /*[out,retval]*/ BSTR * pPattern ) = 0;
      virtual HRESULT __stdcall put_Pattern (
        /*[in]*/ BSTR pPattern ) = 0;
      virtual HRESULT __stdcall get_IgnoreCase (
        /*[out,retval]*/ VARIANT_BOOL * pIgnoreCase ) = 0;
      virtual HRESULT __stdcall put_IgnoreCase (
        /*[in]*/ VARIANT_BOOL pIgnoreCase ) = 0;
      virtual HRESULT __stdcall get_Global (
        /*[out,retval]*/ VARIANT_BOOL * pGlobal ) = 0;
      virtual HRESULT __stdcall put_Global (
        /*[in]*/ VARIANT_BOOL pGlobal ) = 0;
      virtual HRESULT __stdcall raw_Execute (
        /*[in]*/ BSTR sourceString,
        /*[out,retval]*/ IDispatch * * ppMatches ) = 0;
      virtual HRESULT __stdcall raw_Test (
        /*[in]*/ BSTR sourceString,
        /*[out,retval]*/ VARIANT_BOOL * pMatch ) = 0;
      virtual HRESULT __stdcall raw_Replace (
        /*[in]*/ BSTR sourceString,
        /*[in]*/ BSTR replaceString,
        /*[out,retval]*/ BSTR * pDestString ) = 0;
};

struct __declspec(uuid("3f4daca1-160d-11d2-a8e9-00104b365c9f"))
IMatch : IDispatch
{
    //
    // Property data
    //

    __declspec(property(get=GetValue))
    _bstr_t Value;
    __declspec(property(get=GetFirstIndex))
    long FirstIndex;
    __declspec(property(get=GetLength))
    long Length;

    //
    // Wrapper methods for error-handling
    //

    _bstr_t GetValue ( );
    long GetFirstIndex ( );
    long GetLength ( );

    //
    // Raw methods provided by interface
    //

      virtual HRESULT __stdcall get_Value (
        /*[out,retval]*/ BSTR * pValue ) = 0;
      virtual HRESULT __stdcall get_FirstIndex (
        /*[out,retval]*/ long * pFirstIndex ) = 0;
      virtual HRESULT __stdcall get_Length (
        /*[out,retval]*/ long * pLength ) = 0;
};

struct __declspec(uuid("3f4daca2-160d-11d2-a8e9-00104b365c9f"))
IMatchCollection : IDispatch
{
    //
    // Property data
    //

    __declspec(property(get=GetCount))
    long Count;
    __declspec(property(get=GetItem))
    IDispatchPtr Item[];
    __declspec(property(get=Get_NewEnum))
    IUnknownPtr _NewEnum;

    //
    // Wrapper methods for error-handling
    //

    IDispatchPtr GetItem (
        long index );
    long GetCount ( );
    IUnknownPtr Get_NewEnum ( );

    //
    // Raw methods provided by interface
    //

      virtual HRESULT __stdcall get_Item (
        /*[in]*/ long index,
        /*[out,retval]*/ IDispatch * * ppMatch ) = 0;
      virtual HRESULT __stdcall get_Count (
        /*[out,retval]*/ long * pCount ) = 0;
      virtual HRESULT __stdcall get__NewEnum (
        /*[out,retval]*/ IUnknown * * ppEnum ) = 0;
};

struct __declspec(uuid("3f4daca4-160d-11d2-a8e9-00104b365c9f"))
RegExp;
    // [ default ] interface IRegExp

struct __declspec(uuid("3f4daca5-160d-11d2-a8e9-00104b365c9f"))
Match;
    // [ default ] interface IMatch

struct __declspec(uuid("3f4daca6-160d-11d2-a8e9-00104b365c9f"))
MatchCollection;
    // [ default ] interface IMatchCollection

//
// Named GUID constants initializations
//

extern "C" const GUID __declspec(selectany) LIBID_VBScript_RegExp_10 =
    {0x3f4daca7,0x160d,0x11d2,{0xa8,0xe9,0x00,0x10,0x4b,0x36,0x5c,0x9f}};
extern "C" const GUID __declspec(selectany) IID_IRegExp =
    {0x3f4daca0,0x160d,0x11d2,{0xa8,0xe9,0x00,0x10,0x4b,0x36,0x5c,0x9f}};
extern "C" const GUID __declspec(selectany) IID_IMatch =
    {0x3f4daca1,0x160d,0x11d2,{0xa8,0xe9,0x00,0x10,0x4b,0x36,0x5c,0x9f}};
extern "C" const GUID __declspec(selectany) IID_IMatchCollection =
    {0x3f4daca2,0x160d,0x11d2,{0xa8,0xe9,0x00,0x10,0x4b,0x36,0x5c,0x9f}};
extern "C" const GUID __declspec(selectany) CLSID_RegExp =
    {0x3f4daca4,0x160d,0x11d2,{0xa8,0xe9,0x00,0x10,0x4b,0x36,0x5c,0x9f}};
extern "C" const GUID __declspec(selectany) CLSID_Match =
    {0x3f4daca5,0x160d,0x11d2,{0xa8,0xe9,0x00,0x10,0x4b,0x36,0x5c,0x9f}};
extern "C" const GUID __declspec(selectany) CLSID_MatchCollection =
    {0x3f4daca6,0x160d,0x11d2,{0xa8,0xe9,0x00,0x10,0x4b,0x36,0x5c,0x9f}};

//
// interface IRegExp wrapper method implementations
//

inline _bstr_t IRegExp::GetPattern ( ) {
BSTR _result = 0;
HRESULT _hr = get_Pattern(&_result);
if (FAILED(_hr)) _com_issue_errorex(_hr, this, __uuidof(this));
return _bstr_t(_result, false);
}

inline void IRegExp::PutPattern ( _bstr_t pPattern ) {
HRESULT _hr = put_Pattern(pPattern);
if (FAILED(_hr)) _com_issue_errorex(_hr, this, __uuidof(this));
}

inline VARIANT_BOOL IRegExp::GetIgnoreCase ( ) {
VARIANT_BOOL _result = 0;
HRESULT _hr = get_IgnoreCase(&_result);
if (FAILED(_hr)) _com_issue_errorex(_hr, this, __uuidof(this));
return _result;
}

inline void IRegExp::PutIgnoreCase ( VARIANT_BOOL pIgnoreCase ) {
HRESULT _hr = put_IgnoreCase(pIgnoreCase);
if (FAILED(_hr)) _com_issue_errorex(_hr, this, __uuidof(this));
}

inline VARIANT_BOOL IRegExp::GetGlobal ( ) {
VARIANT_BOOL _result = 0;
HRESULT _hr = get_Global(&_result);
if (FAILED(_hr)) _com_issue_errorex(_hr, this, __uuidof(this));
return _result;
}

inline void IRegExp::PutGlobal ( VARIANT_BOOL pGlobal ) {
HRESULT _hr = put_Global(pGlobal);
if (FAILED(_hr)) _com_issue_errorex(_hr, this, __uuidof(this));
}

inline IDispatchPtr IRegExp::Execute ( _bstr_t sourceString ) {
IDispatch * _result = 0;
HRESULT _hr = raw_Execute(sourceString, &_result);
if (FAILED(_hr)) _com_issue_errorex(_hr, this, __uuidof(this));
return IDispatchPtr(_result, false);
}

inline VARIANT_BOOL IRegExp::Test ( _bstr_t sourceString ) {
VARIANT_BOOL _result = 0;
HRESULT _hr = raw_Test(sourceString, &_result);
if (FAILED(_hr)) _com_issue_errorex(_hr, this, __uuidof(this));
return _result;
}

inline _bstr_t IRegExp::Replace ( _bstr_t sourceString, _bstr_t replaceString ) {
BSTR _result = 0;
HRESULT _hr = raw_Replace(sourceString, replaceString, &_result);
if (FAILED(_hr)) _com_issue_errorex(_hr, this, __uuidof(this));
return _bstr_t(_result, false);
}

//
// interface IMatch wrapper method implementations
//

inline _bstr_t IMatch::GetValue ( ) {
BSTR _result = 0;
HRESULT _hr = get_Value(&_result);
if (FAILED(_hr)) _com_issue_errorex(_hr, this, __uuidof(this));
return _bstr_t(_result, false);
}

inline long IMatch::GetFirstIndex ( ) {
long _result = 0;
HRESULT _hr = get_FirstIndex(&_result);
if (FAILED(_hr)) _com_issue_errorex(_hr, this, __uuidof(this));
return _result;
}

inline long IMatch::GetLength ( ) {
long _result = 0;
HRESULT _hr = get_Length(&_result);
if (FAILED(_hr)) _com_issue_errorex(_hr, this, __uuidof(this));
return _result;
}

//
// interface IMatchCollection wrapper method implementations
//

inline IDispatchPtr IMatchCollection::GetItem ( long index ) {
IDispatch * _result = 0;
HRESULT _hr = get_Item(index, &_result);
if (FAILED(_hr)) _com_issue_errorex(_hr, this, __uuidof(this));
return IDispatchPtr(_result, false);
}

inline long IMatchCollection::GetCount ( ) {
long _result = 0;
HRESULT _hr = get_Count(&_result);
if (FAILED(_hr)) _com_issue_errorex(_hr, this, __uuidof(this));
return _result;
}

inline IUnknownPtr IMatchCollection::Get_NewEnum ( ) {
IUnknown * _result = 0;
HRESULT _hr = get__NewEnum(&_result);
if (FAILED(_hr)) _com_issue_errorex(_hr, this, __uuidof(this));
return IUnknownPtr(_result, false);
}

#pragma pack(pop)

struct          cxx_regex
{
    cxx_regex(int cflags = 0) : m_com_regexp(), m_cflags(cflags) {}

    CComPtr<IRegExp>    m_com_regexp;
    int                 m_cflags;
};

typedef struct  cxx_regmatch_s
{
    void        *dummy;
}               cxx_regmatch_t;

int regcomp(regex_t *preg, const char *pattern, int cflags)
{
    preg->cxx_regex = NULL;

    static int co_init = 0;

    if (co_init == 0)
    {
        CoInitialize(NULL);
        co_init = 1;
    }

    cxx_regex *cr = new cxx_regex;

    HRESULT hr = cr->m_com_regexp.CoCreateInstance(CLSID_RegExp);
    if (FAILED(hr))
    {
        delete cr;
        return -1;
    }

    try
    {
        cr->m_com_regexp->PutPattern(pattern);
        cr->m_com_regexp->PutGlobal(VARIANT_TRUE);
        preg->cxx_regex = (void *)cr;
    }
    catch (_com_error const&)
    {
        delete cr;
        return -1;
    }

    preg->cxx_regex = (void *)cr;

    return 0;
}

int regwcomp(regex_t *preg, const wchar_t *pattern, int cflags)
{
    preg->cxx_regex = NULL;

    static int co_init = 0;

    if (co_init == 0)
    {
        CoInitialize(NULL);
        co_init = 1;
    }

    cxx_regex *cr = new cxx_regex;

    HRESULT hr = cr->m_com_regexp.CoCreateInstance(CLSID_RegExp);
    if (FAILED(hr))
    {
        delete cr;
        return -1;
    }

    try
    {
        cr->m_com_regexp->PutPattern(pattern);
        preg->cxx_regex = (void *)cr;
    }
    catch (_com_error const&)
    {
        delete cr;
        return -1;
    }

    preg->cxx_regex = (void *)cr;

    return 0;
}

size_t regerror(int errcode, const regex_t *preg, char *errbuf, size_t errbuf_size)
{
    /* Not implemented ! */
    return 0;
}

int regexec(const regex_t *preg, const char *string, size_t nmatch, regmatch_t *pmatch, int eflags)
{
    cxx_regex *cr = (cxx_regex *)preg->cxx_regex;
    if (cr == NULL)
        return -1;

    try
    {
        if (cr->m_com_regexp->Test(string) == VARIANT_TRUE)
            return 0;
    }
    catch (_com_error const&)
    {
        return -1;
    }

    return REG_NOMATCH;
}

int regwexec(const regex_t *preg, const wchar_t *string, size_t nmatch, regmatch_t *pmatch, int eflags)
{
    cxx_regex *cr = (cxx_regex *)preg->cxx_regex;
    if (cr == NULL)
        return -1;

    try
    {
        if (cr->m_com_regexp->Test(string) == VARIANT_TRUE)
            return 0;
    }
    catch (_com_error const&)
    {
        return -1;
    }

    return REG_NOMATCH;
}

void regfree(regex_t *preg)
{
    cxx_regex *cr = (cxx_regex *)preg->cxx_regex;
    cr->m_com_regexp.Release();
    delete cr;
    preg->cxx_regex = NULL;
}
