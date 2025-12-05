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

OverlayDialog  {
  id: customSocks5ProxyDialog
  buttons: [Dialog.Ok, Dialog.Cancel]
  canAccept: proxyHostname.acceptableInput
  contentWidth: 300
  title: uiTranslate("ConnectionPage", "SOCKS5 Proxy")

  function updateAndOpen() {
    var currentCustomProxy = Daemon.settings.proxyCustom
    proxyHostname.setting.currentValue = currentCustomProxy.host
    if (currentCustomProxy.port > 0 && currentCustomProxy.port <= 65535)
      proxyPort.setting.currentValue = currentCustomProxy.port.toString()
    else {
      proxyPort.setting.currentValue = ""
      proxyPort.placeholderText.visible = true
    }

    proxyUsername.setting.currentValue = currentCustomProxy.username
    proxyPassword.setting.currentValue = currentCustomProxy.password

    open()
  }

  GridLayout {
    width: parent.width
    columns: 2
    TextboxInput {
      textBoxVerticalPadding: 4
      id: proxyHostname
      Layout.fillWidth: true
      //: The IP address of the SOCKS proxy server to use when
      //: connecting.  Labeled with "IP Address" to indicate that it
      //: can't be a hostname.
      label: uiTranslate("ConnectionPage", "Server IP Address")
      setting: Setting {
        sourceValue: ""
      }
      // Only IP addresses allowed.  This regex allows leading zeros in each
      // part.
      validator: RegularExpressionValidator {
        regularExpression: /(([0-1]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-1]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])/
      }
    }
    TextboxInput {
      textBoxVerticalPadding: 4
      id: proxyPort
      label: uiTranslate("ConnectionPage", "Port")
      setting: Setting {
        sourceValue: ""
      }
      placeholderText: uiTranslate("ConnectionPage", "Default")
      validator: RegularExpressionValidator {
        regularExpression: /^(|0|[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$/
      }
    }
    TextboxInput {
      textBoxVerticalPadding: 4
      id: proxyUsername
      Layout.fillWidth: true
      Layout.columnSpan: 2
      label: uiTranslate("ConnectionPage", "User (optional)")
      setting: Setting {
        sourceValue: ""
      }
    }
    TextboxInput {
      textBoxVerticalPadding: 4
      id: proxyPassword
      Layout.fillWidth: true
      Layout.columnSpan: 2
      label: uiTranslate("ConnectionPage", "Password (optional)")
      masked: true
      setting: Setting {
        sourceValue: ""
      }
    }
  }

  onAccepted: {
    // Addressing a Qt 6.2.4 issue that happens only on macos.
    // Refer to the same comment in the SplitTunnelAddIpDialog page for context
    proxyHostname.focus = false
    proxyPort.focus = false
    proxyUsername.focus = false
    proxyPassword.focus = false
    Daemon.applySettings({
                            "proxyType": "custom",
                            "proxyCustom": {
                              "host": proxyHostname.setting.currentValue,
                              "port": Number(proxyPort.setting.currentValue),
                              "username": proxyUsername.setting.currentValue,
                              "password": proxyPassword.setting.currentValue
                            }
                          })
    socksHeading.focusButton();
  }
  onRejected: {
    socksHeading.focusButton();
  }
}
