# Private Internet Access Desktop Client

This is the desktop client for the Private Internet Access VPN service. It consists of an unprivileged thin GUI client (the "client") and a privileged background service/daemon (the "daemon"). The daemon runs a single instance on the machine and is responsible for not only network configuration but also settings and account handling, talking to PIA servers as necessary. The client meanwhile runs in each active user's desktop and consists almost entirely of presentation logic. No matter how many users are active on a machine, they control the same single VPN instance and share a single PIA account.

The project uses Qt 6.2 for cross-platform development, both in the client and daemon. The client GUI is based on Qt Quick, which uses declarative markup language and JavaScript and offers hardware accelerated rendering when available. Qt and Qt Quick tend to be more memory and CPU efficient compared to web-based UI frameworks like Electron or NW.js.

## Building and developing

The client is intended to be built on the target platform; Windows builds are built on Windows, macOS builds on macOS, and Linux builds on Debian.

The entire product is built using rake, using the supporting framework in the `rake/` directory.

Dependencies such as [OpenVPN](https://github.com/pia-foss/desktop-dep-build) and the [Windows TAP driver](https://github.com/pia-foss/desktop-tap) are included as precompiled binaries under the `deps` directory in this project for convenience. To recompile any of these, please refer to their corresponding directories and/or repositories for build instructions.

### Cloning the repository

Before cloning the Git repository, first make sure [Git LFS is installed](https://github.com/git-lfs/git-lfs/wiki/Installation) and initialized:

```console
> git lfs version
git-lfs/2.3.4 (GitHub; windows amd64; go 1.8.3; git d2f6752f)

> git lfs install
Updated git hooks.
Git LFS initialized.
```

After this, cloning the repository normally should also fetch the precompiled binaries:

```console
> git clone https://github.com/pia-foss/desktop.git
...
Filtering content: 100% (24/24), 17.13 MiB | 1.89 MiB/s, done.
```

### Prerequisites

- On **Windows** (x86_64, arm64):
  - Using git from git bash instead of powershell is recommended, due to some knows bugs in Windows built-in openssh service in regards to git-lfs. 
  - Use chocolatey from an admin powershell session [chocolatey.org/install](https://chocolatey.org/install) running:
    - `choco install ruby 7Zip git git-lfs`
  - [Qt 6.2.4](https://www.qt.io/download)
    - Follow this process if you want to be able to fully debug into Qt code and QML:  
      - Download Qt from the official website: https://www.qt.io/download-open-source, scroll down and click "Download the Qt Online Installer"
      - The installer name should look like this "qt-unified-windows-x64-4.6.0-online.exe"
      - You will need to create an account and login
      - Select path C:\Qt and "Custom installation"
      - When selecting components check these boxes:
        - Qt / Qt 6.2.4 / MSVC2019 32-bit, MSVC2019 64-bit, Sources, Qt Debug Information Files
        - Qt / Developer and Designer Tools / Qt Creator, ...CDB Debugger support, Debugging Tools for Windows, CMake
      - (optional) If you have multiple installations of Qt, set user environment variable `QTROOT` to `C:\Qt\6.2.4`
    - Otherwise, use aqtinstall if you just need to build the client:  
      - Run these commands in Powershell with admin priviledges
      - `choco install python`
      - Close Powershell and open a new Admin instance
      - `pip install aqtinstall`
      - `mkdir C:\Qt-aqt`
      - `aqt install-qt -O "C:/Qt-aqt" windows desktop 6.2.4 win64_msvc2019_64`
      - (optional for windows arm64) 
        - `aqt install-qt -O "C:/Qt-aqt" windows desktop 6.2.4 win64_msvc2019_arm64`
      - (optional) If you have multiple installations of Qt
        - set user environment variable `QTROOT` to `C:\Qt-aqt\6.2.4`
  - [Visual Studio 2022](https://visualstudio.microsoft.com/vs/)
     - Can install with choco with `choco install visualstudio2022community`
     - Once installed, open the `Visual Studio Installer` app.
     - Click on "More" -> "Import configuration"
     - Select the config file in `scripts-internal/pia-default.vsconfig`
     - It will install everything you should need, but you can add more components as needed.
     - The VS installer doesn't include the Console Debugger (CDB), which is needed to debug in Qt Creator.  More info: [Setting Up Debugger](https://doc.qt.io/qtcreator/creator-debugger-engines.html)
- On **macOS**:
  - Qt 6.2.4
    - PIA's universal build of Qt is recommended: [desktop-dep-build releases](https://github.com/pia-foss/desktop-dep-build/releases)
    - The universal Qt build can be used for universal or single-architecture PIA builds.
    - If you want Qt Creator, also install Qt from [qt.io](https://www.qt.io/download)
  - Big Sur or newer is required to build
  - Up-to-date version of Xcode
  - Ruby, can be installed using [Homebrew](https://brew.sh) with `brew install ruby`
  - Install rake: `sudo gem install rake`
- On **Linux**:
  - Supported distribution with clang 11 or newer
  - Supported architectures: x86_64, arm64
  - Qt 6.2.4 or later
    - PIA's build of Qt is recommended: [desktop-dep-build releases](https://github.com/pia-foss/desktop-dep-build/releases)
    - If you want Qt Creator, also install Qt from [qt.io](https://www.qt.io/download)
  - Host build (Debian 11+ and derivatives):
    - `sudo apt install build-essential rake clang mesa-common-dev libnl-3-dev libnl-route-3-dev libnl-genl-3-dev git git-lfs`
  - Host build (Arch and derivatives):
    - `sudo pacman -S base-devel git-lfs ruby-rake clang llvm libnl zip`
  - Debian 11 docker image build (used to build published releases for maximum compatibility, and for cross builds)
    - See [Building for Distribution](docs/Building-for-distribution.md)

### Running and debugging

Each platform requires additional installation steps in order for the client to be usable (e.g. the Windows TAP adapter needs to be installed).  
The easiest way to perform these steps is to build and run an installer, after which you can stop and run individual executables in a debugger instead.

To debug your own daemon, the installed daemon must first be stopped:

- **Windows**: Run `services.msc` and stop the Private Internet Access Service. Set it to manual
- **macOS**: Run `sudo launchctl unload /Library/LaunchDaemons/com.privateinternetaccess.vpn.daemon.plist`
- **Linux**: Run `sudo systemctl stop piavpn`

The daemon must run as root. Consult your IDE/debugger documentation for how to safely run the debugger target as root.

**Windows** only: 
  - If you have installed Qt using the official installer, add `C:\Qt\6.2.4\msvc2019_64\bin` to your user environment variable path.   
    This is needed if you want to run `pia-client.exe` or `pia-service.exe` via command line.
  - To run the pia-daemon, execute `.\pia-service.exe run` in Powershell with admin privileges

To check PIA logs, go to your `*installation_path*\data` (The default path on Windows is `C:\Program Files\Private Internet Access\data`).  
In order to enable all the logs, in PIA app *Settings* page go to Help and select *Enable Debug Logging*.

### Quick start

* To build the final installer for the host OS and architecture: `rake installer`
  * Produced in `out/pia_debug_<arch>/installer`
* To build all artifacts for the host OS and architecture: `rake all`
  * Artifacts go to `out/pia_debug_<arch>/artifacts`
* To build just the staged installation for development: `rake`
  * Staged installation is in `out/pia_debug_<arch>/stage` - run the client or daemon from here
* To run tests: `rake test`
* To build for release instead of debug, set `VARIANT=release` with any of the above

### Updating the built dependencies

Linux: check that the symbolic links are correct using `ls -lah -R deps/built/linux/`.  
If they are not, create them using `ln -sf libfile linkname`.

### Build system

The following targets can be passed to `rake`.  The default target is `stage`, which stages the built client, daemon, and dependencies for local testing (but does not build installers, tests, etc.)

| Target | Explanation |
|--------|-------------|
| (default) | Builds the client and daemon; stages executables with dependencies in `out/pia_debug_x86_64/stage` for local testing. |
| `test` | Builds and runs unit tests; produces code coverage artifacts if possible on the current platform (requires clang 6+) |
| `installer` | Builds the final installer artifact, including code signing if configured. |
| `export` | Builds extra artifacts needed from CI but not part of any deployable artifact (currently translation exports) |
| `libs` | Builds the dtop libraries and development artifact (see DTOP-LIBS.md) |
| `tools` | Builds extra tools for development purposes that are not used as part of the build process or as part of any shipped artifact. |
| `artifacts` | Builds all artifacts and copies to `out/pia_debug_x86_64/artifacts` (depends on most other targets, execpt `test` when coverage measurement isn't possible) |
| `all` | All targets. |

#### Configurations

The build system has several properties that can be configured, either in the environment or by passing the appropriate variables to `rake`.

These are implemented in `rake/build.rb`.  The output directory name includes the current brand, variant, and architecture.

| Variable | Values | Default | Explanation |
|----------|--------|---------|-------------|
| `VARIANT` | `debug`, `release` | `debug` | Create a debug build (unoptimized, some compression levels reduced for speed), or release build (optimized, maximum compression). |
| `ARCHITECTURE` | `x86_64`, `x86`, `arm64`, `arm64e`, `armhf`, `universal` | Host architecture | Select an alternate architecture.  Architecture support varies by platform. |
| `PLATFORM` | `windows`, `macos`, `linux`, `android`, `ios`, `iossim` | Host platform | Select an alternate platform.  Android and iOS targets only build core libraries and tests.  Android builds can be performed from macOS or Linux hosts.  iOS and iOS Simulator builds can be performed from macOS hosts. |
| `BRAND` | (directories in `brands/`) | `pia` | Build an alternate brand. |

#### Variables

Some additional environment variables can be configured:

| Variable | Example | Explanation |
|----------|---------|-------------|
| `QTROOT` | /opt/Qt/6.2.4 | Path to the installed Qt version, if qt.rb can't find it or you want to force a specific version |

### Mac installation

Installation on Mac uses `SMJobBless` to install a privileged helper that does the installation.

Mac OS requires the app to be signed in order to install and use the helper.  If the app is not signed, it will not be able to install or uninstall itself (you can still install or uninstall manually by running the install script with `sudo`.)

`PIA_CODESIGN_CERT` must be set to the full common name of the certificate to sign with.  (`codesign` allows a partial match, but the full CN is needed for various Info.plist files.)

To test installation, you can generate a self-signed certificate and sign with that.

* Open Keychain Access
* Create a new keychain
   1. Right-click in the Keychains pane and select "New Keychain..."
   2. Give it a name (such as "PIA codesign") and password
* Generate a self-signed code signing certificate
   1. Select your new keychain
   2. In the menu bar, select Keychain Access > Certificate Assistant > Create a Certificate...
   3. Enter a name, such as "PIA codesign", it does not have to match the keychain name
   4. Keep the default identity type "Self Signed Root"
   5. Change the certificate type to "Code Signing"
   6. Click Create, then Continue
* Optional - disable "lock after inactivity" for your keychain
   1. Right-click on the keychain and select "Change Settings for Keychain"
   2. Turn off locking options as desired
* Use the certificate to sign your PIA build
   * Qt Creator:
      1. Select Projects on the left sidebar, and go to the build settings for your current kit
      2. Expand "Build Environment"
      3. Add a new variable named `PIA_CODESIGN_CERT`, and set the value to the common name for your certificate
   * Manual builds with `build-macos.sh`
      1. Just set `PIA_CODESIGN_CERT` to the common name you gave the certificate when building

## Core Libraries

**Note:** building for android and ios is deprecated and unsupported at the time.

Some core libraries can be built targeting Android and iOS for use in our mobile clients.

### Prerequisites

- For **Android** targets:
  - Linux or macOS host.  Windows hosts are not currently supported for Android builds.
  - Ruby and Rake:
    - Debian: `sudo apt install rake`
    - Arch: `sudo pacman -S ruby-rake`
    - macOS Homebrew: `brew install ruby` (includes Rake)
  - Android NDK 21.0.6113669 (preferred) or any later version
    - You can install this from Android Studio or using the command-line SDK tools
- For **iOS** targets:
  - macOS host, up-to-date version of Xcode
  - Ruby and Rake:
    - macOS Homebrew: `brew install ruby` (includes Rake)

### Building

Invoke `rake` with `PLATFORM=android` or `PLATFORM=ios` to target a mobile platform.
You can also set `ARCHITECTURE` to one of `arm64`, `armhf`, `x86_64`, or `x86` - the host architecture is the default. 
If you do this a lot, you can place overrides in your environment or .buildenv to use these by default.

(Qt does not need to be installed for mobile targets.)

### Build system

The same `rake`-based build system is used, but the available targets differ.

| Target | Explanation |
|--------|-------------|
| (default) | Stages core libraries with dependencies in `out/pia_debug_<platform>_<arch>/dtop-libs` for local testing. |
| `libs_archive` | Builds the library SDK ZIP containing the built libraries and headers. |
| `tools` | Builds libraries and internal test harnesses used to test them. |
| `artifacts` | Builds all artifacts and copies to `out/pia_debug_<platform>_<arch>/artifacts` (depends on most other targets) |
| `all` | All targets. |

### Automated testing

In the `headless_tests` directory you will find a suite of tests written in ruby with the help of RSpec.
They use `piactl` in the background to manipulate the state of the daemon and run diverse tests.
The advantage of testing in ruby is mainly simplicity, where doing things like calling API endpoints is much simpler than from C++ code.

With these _almost_ end to end tests we hope to drastically reduce manual testing for releases to the point that we can release more frequently.  

Use `bundle install` from the `headless_tests` directory to ensure you get all the dependencies.  
Run the tests from within the `headless_tests` to pick up configuration in `.rspec` and `spec_helper`.
Run all tests locally using `bundle exec rspec .`.

#### Windows

Add `C:\Program Files\Private Internet Access` to your user environment variable Path in order to be able to run `piactl` from the command line. (You can still run piactl using the full path, but the headless tests won't work).

## Contributing

By contributing to this project you are agreeing to the terms stated in the [Contributor License Agreement](CLA.md). For more details please see our [Contribution Guidelines](https://pia-foss.github.io/contribute) or [CONTRIBUTING](/CONTRIBUTING.md).

## Licensing

Unless otherwise noted, original source code is licensed under the GPLv3. See [LICENSE](/LICENSE.txt) for more information.
