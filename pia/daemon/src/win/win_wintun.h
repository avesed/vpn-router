// Copyright (c) 2025 Private Internet Access, Inc.
//
// This file is part of the Private Internet Access Desktop Client.
//
// The Private Internet Access Desktop Client is free software: you can
// redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// The Private Internet Access Desktop Client is distributed in the hope that
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the Private Internet Access Desktop Client.  If not, see
// <https://www.gnu.org/licenses/>.

#ifndef WIN_WINTUN_H
#define WIN_WINTUN_H

#include <common/src/win/win_util.h>
#include <deps/wintun/src/wintun.h>

namespace WintunData
{
    // Name used for the OpenVPN WinTUN adapter
    extern const wchar_t *pOpenVPNName;
}

namespace WintunPools
{
    // WinTUN pool names used for WireGuard and OpenVPN connections.
    extern const wchar_t *pWireGuardPool;
    extern const wchar_t *pOpenVPNPool;
}

class WintunAdapter
{
public:
    WintunAdapter() : _handle{}, _pWTCloseAdapter{} {
        qInfo() << "Constructed empty wintun adapter";
    }

    WintunAdapter(WINTUN_ADAPTER_HANDLE handle, WINTUN_CLOSE_ADAPTER_FUNC* pWTCloseAdapter)
        : _handle{handle}, _pWTCloseAdapter{pWTCloseAdapter}
    {
        qInfo() << "Constructed handling wintun adapter" << _handle;
        // If we got a valid handle, we _must_ have a WintunFreeAdapter
        // function to free it.  (It can be nullptr though if we didn't get
        // a handle.)
        Q_ASSERT(_pWTCloseAdapter || !_handle);
    }

    ~WintunAdapter()
    {
        if(!_handle)
            return;

        qInfo() << "Deleting WintunAdapter handle";
        _pWTCloseAdapter(_handle);
    }

    WintunAdapter(WintunAdapter &&other) : WintunAdapter{} {
        qInfo() << "MOved WintunAdapter";
        this->_handle = other._handle;
        this->_pWTCloseAdapter = other._pWTCloseAdapter;
    }
    WintunAdapter (const WintunAdapter&) = delete;
    WintunAdapter& operator= (const WintunAdapter&) = delete;

public:
    explicit operator bool() const {return get();}
    operator WINTUN_ADAPTER_HANDLE() const {return get();}
    WINTUN_ADAPTER_HANDLE get() const {return _handle;}

private:
    WINTUN_ADAPTER_HANDLE _handle{};
    WINTUN_CLOSE_ADAPTER_FUNC* _pWTCloseAdapter{};
};

// Loads the WinTUN module, initializes logging, and loads used entry
// points.  Provides wrappers for entry points returning adapter handles
// as std::shared_ptr<WintunAdapter>
class WintunModule
{
public:
    WintunModule();

private:
    // Infer the function pointer type from one of the members below
    template<class T>
    void loadProc(T &pProc, const char *name) const
    {
        pProc = _module.getProcAddress<T>(name);
    }

    // Wrap a returned WINTUN_ADAPTER_HANDLE in a WintunAdapter owner
    std::shared_ptr<WintunAdapter> ownHandle(WINTUN_ADAPTER_HANDLE handle) const
    {
        return std::make_shared<WintunAdapter>(handle, _pWTCloseAdapter);
    }

public:
    // API wrappers - no-ops if entry points failed to load; wraps
    // WINTUN_ADAPTER_HANDLE results in WintunAdapter
    std::shared_ptr<WintunAdapter> createAdapter(const WCHAR *Name, const WCHAR *Type,
        const GUID *RequestedGUID) const
    {
        if(!_pWTCreateAdapter)
            return {};
        return ownHandle(_pWTCreateAdapter( Name, Type, RequestedGUID));
    }

    std::shared_ptr<WintunAdapter> openAdapter(const WCHAR *name) const
    {
        if(!_pWTOpenAdapter)
            return {};
        auto adapterHandle = _pWTOpenAdapter(name);
        if(!adapterHandle)
            return {};
        return ownHandle(adapterHandle);
    }

    VOID closeAdapter(WINTUN_ADAPTER_HANDLE Adapter, BOOL ForceCloseSessions,
        BOOL *RebootRequired) const
    {
        if(!_pWTCloseAdapter)
            return;
        qInfo() << "Closing adapter from function";
        _pWTCloseAdapter(Adapter);
    }

    BOOL deleteDriver() const
    {
        if(!_pWTDeleteDriver)
            return FALSE;
        return _pWTDeleteDriver();
    }

    void getAdapterLuid(WINTUN_ADAPTER_HANDLE Adapter, NET_LUID *Luid) const
    {
        if(!_pWTGetAdapterLuid)
            return;
        _pWTGetAdapterLuid(Adapter, Luid);
    }

    // Wrapper for enumAdapters() using a stateful functor (adapts the functor
    // to a callback function and LPARAM state pointer).
    // Note that we do _not_ wrap the WINTUN_ADAPTER_HANDLE that the callback
    // receives, as we don't own it - WintunEnumAdapters() frees it when the
    // callback returns.
    template<class Func_t>
    BOOL enumAdapters(const WCHAR *Pool, Func_t adapterFunc) const
    {
        // Stateless shim to adapt the callback
        auto enumCallbackShim = [](WINTUN_ADAPTER_HANDLE Adapter, LPARAM Param) -> BOOL
        {
            auto pCallback = reinterpret_cast<Func_t*>(Param);
            Q_ASSERT(pCallback);    // Ensured by caller (below)
            return pCallback->operator()(Adapter);
        };
        return enumAdapters(Pool, enumCallbackShim, reinterpret_cast<LPARAM>(&adapterFunc));
    }

    // Recreate a WinTUN adapter
    std::shared_ptr<WintunAdapter> recreateAdapter(const WCHAR *Name) const;

private:
    WinModule _module;
    WINTUN_CREATE_ADAPTER_FUNC* _pWTCreateAdapter;
    WINTUN_OPEN_ADAPTER_FUNC* _pWTOpenAdapter;
    WINTUN_CLOSE_ADAPTER_FUNC* _pWTCloseAdapter;
    WINTUN_DELETE_DRIVER_FUNC* _pWTDeleteDriver;
    WINTUN_GET_ADAPTER_LUID_FUNC* _pWTGetAdapterLuid;
    WINTUN_SET_LOGGER_FUNC* _pWTSetLogger;
};

#endif
