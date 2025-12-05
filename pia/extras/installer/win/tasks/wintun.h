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

#ifndef TASKS_WINTUN_H
#define TASKS_WINTUN_H

#include "../tasks.h"

// These tasks handle uninstallation of the WinTUN driver package - both the
// legacy MSI package, and the current driver deployed by pia-wintun.dll.
// 
// In PIA 2.0-2.9, WinTUN was deployed as a shared component using an MSI.
// Installation of 2.10+ uninstalls this MSI if it is present, since it is no
// longer used.
// 
// PIA 2.10+ ships pia-wintun.dll, which includes the PIA-branded WinTUN driver
// as a resource and deploys it automatically.  We don't need to do anything
// during installation.  When uninstalling PIA, we call a WinTUN entry point
// to remove the driver package.

// Uninstall the legacy WinTUN MSI package.  Used when installing 2.10+.
class UninstallWintunMsiTask : public Task
{
public:
    using Task::Task;
    virtual void execute() override;
    virtual void rollback() override;
    virtual double getEstimatedExecutionTime() const override { return 2.0; }
};

// Uninstall the branded WinTUN driver using pia-wintun.dll.  Used when
// uninstalling 2.10+.
class UninstallWintunTask : public Task{
public:
    using Task::Task;
    virtual void execute() override;
    // No rollback; pia-wintun.dll will install the driver when connecting as
    // needed
    virtual double getEstimatedExecutionTime() const override { return 2.0; }
};

#endif
