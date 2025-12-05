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

#include "common.h"
#line SOURCE_FILE("apinetwork.cpp")

#include "apinetwork.h"
#include "testshim.h"
#include <algorithm>
#include <QNetworkProxyFactory>
#include <atomic>

namespace
{
    // Counter used to vary the proxy username.
    //
    // QNetworkAccessManager caches connections, and we can no longer clear the
    // cache for every attempt like we did in Qt 5.11 - since 5.12 clearing the
    // cache terminates in-flight requests, because it kills the worker thread.
    // (It has to kill the thread, because the caches now are thread-local
    // objects on that thread.)
    //
    // The proxy username is included in the cache key, so we can trick it into
    // never reusing connections by varying the proxy username, at least when
    // the proxy is active.
    //
    // Clearing the cache when we know we're connecting/disconnecting is also
    // beneficial, but this is difficult to time sufficiently well to guarantee
    // that reusing connections is safe, particularly given that some VPN
    // interface setup is done asynchronously (such as configuring the interface
    // IP with WireGuard on Windows).
    //
    // This is atomic in case it might be used from QNAM's HTTP worker thread.
    std::atomic<std::uint32_t> proxyUsernameCounter;

    // A QNetworkProxyFactory that always returns the same proxy, but with a
    // varying username to trick the QNAM connection cache.  See
    // ApiNetwork::setProxy().
    class UsernameCounterProxyFactory : public QNetworkProxyFactory
    {
    public:
        UsernameCounterProxyFactory(QNetworkProxy proxy) : _proxy{std::move(proxy)} {}

    public:
        virtual QList<QNetworkProxy> queryProxy(const QNetworkProxyQuery &) override
        {
            QNetworkProxy result{_proxy};
            std::uint32_t counter = proxyUsernameCounter++;
            result.setUser(result.user() + QString::number(counter));
            return {std::move(result)};
        }

    private:
        const QNetworkProxy _proxy;
    };
}

ApiNetwork::ApiNetwork()
{
    _pAccessManager.reset(TestShim::create<QNetworkAccessManager>());
}

void ApiNetwork::setProxy(QNetworkProxy proxy)
{
    // If we were to set the proxy with QNetworkAccessManager::setProxy(), then
    // it will assume that the proxy can only handle one request at a time.
    // That means that after connecting, when we try to refresh all regions
    // lists (as well as PF, login, etc.), only one request will go through at
    // a time, and the others could time out before they get a chance to use the
    // proxy.
    //
    // Insead, use a proxy factory, which returns a new QNetworkProxy object for
    // every request (with the same proxy configuration every time).  This
    // allows all requests to use the proxy at the same time.
    //
    // Additionally, this proxy factory varies the username in order to trick
    // the QNAM connection cache.
    getAccessManager().setProxyFactory(new UsernameCounterProxyFactory{std::move(proxy)});
    // Clear the connection cache now.  It's possible that ongoing request might
    // actually complete in this case, but since we're starting the proxy we
    // want to abandon them anyway.
    getAccessManager().clearConnectionCache();
}

void ApiNetwork::clearProxy()
{
    getAccessManager().setProxyFactory(nullptr);
    // Clear the connection cache now.  This kills any ongoing requests, but
    // since we're shutting down the proxy, that's fine.
    getAccessManager().clearConnectionCache();
}

QNetworkAccessManager &ApiNetwork::getAccessManager() const
{
    Q_ASSERT(_pAccessManager);  // Class invariant
    return *_pAccessManager;
}

template class COMMON_EXPORT AutoSingleton<ApiNetwork>;
