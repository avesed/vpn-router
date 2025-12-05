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

import QtQuick 2.15
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.3
import QtQuick.Window 2.11
import "../"
import "../../inputs"
import PIA.NativeHelpers 1.0
import "../../stores"
import "../../../common"
import "../../../client"
import "../../../daemon"
import "../../../theme"
import "../../../common/regions"

OverlayDialog {
  id: selectShadowsocksRegionDialog
  buttons: [Dialog.Ok, Dialog.Cancel]
  canAccept: true
  contentWidth: 350
  title: "Shadowsocks" // Not translated
  topPadding: 0
  bottomPadding: 0
  leftPadding: 0
  rightPadding: 0

  function updateAndOpen() {
    shadowsocksRegionList.chosenLocation = Daemon.state.shadowsocksLocations.chosenLocation
    shadowsocksRegionList.clearSearch()
    shadowsocksRegionList.reevalSearchPlaceholder()
    open()
  }

  RegionList {
    id: shadowsocksRegionList
    width: parent.width
    implicitHeight: 450
    regionFilter: function (serverLocation) {
      // Show regions that have at least one shadowsocks server
      return serverLocation.hasShadowsocks
    }
    // Don't use shadowsocksLocations directly since the chosen location
    // isn't applied until the user clicks OK
    property var chosenLocation
    // assigned in updateAndOpen() or onRegionSelected()
    serviceLocations: ({
                          "bestLocation": Daemon.state.shadowsocksLocations.bestLocation,
                          "chosenLocation": shadowsocksRegionList.chosenLocation
                        })
    portForwardEnabled: false
    canFavorite: false
    collapsedCountriesSettingName: "shadowsocksCollapsedCountries"
    onRegionSelected: {
      // Update chosenLocation - null if 'auto' or an unknown region was
      // selected
      shadowsocksRegionList.chosenLocation = Daemon.state.availableLocations[locationId]
    }
  }

  onAccepted: {
    var regionId = 'auto'
    if (shadowsocksRegionList.chosenLocation)
      regionId = shadowsocksRegionList.chosenLocation.id
    Daemon.applySettings({
                            "proxyType": "shadowsocks",
                            "proxyShadowsocksLocation": regionId
                          })
    shadowsocksHeading.focusButton();
  }
  onRejected: {
    shadowsocksHeading.focusButton();
  }
}
