# How to Download Qt 6.2.4

## MacOS

* `brew install python3`
* `python3 -m pip install aqtinstall`
* `mkdir ~/Qt6`
* `cd ~/Qt6`
* `aqt install-qt mac desktop 6.2.4`  
* `mv ~/Qt6/6.2.4/macos ~/Qt6/6.2.4/clang_universal`
* `export QTROOT=/Users/user/Qt6/6.2.4`
* `rake stage`

Get Qt sources from [Qt Github repository](https://github.com/qt/qtbase)

# Updating Qt Version

## Step 0 - Update Qt locally and verify functionality

* Update your local Qt install
* Perform a build
* Verify major functionality working correctly

## Step 1 - Update build agents

* Ensure all jobs have finished running, and no critical pushes are coming up soon.
* Stop all build agents on the [gitlab group runner config](https://codex.londontrustmedia.com/groups/research/-/settings/ci_cd)
* Log into individual build servers and run the maintainance tool. See [notes on connecting]('./build-server-remote-desktop) to build servers.

#### Windows

* Qt is installed in C:\Qt\
* Run the MaintainanceTool.exe
* The Qt account username and password is in `Documents/qt_pass.txt`, if a login is required
* Please ensure you select "Qt Debug Information Files" for the version of Qt that you are installing
* Select the following compiler targets:
  * MSVC 2017 32-Bit
  * MSVC 2017 64-Bit

#### Linux

* Qt is installed in /opt/Qt/
* Run `./MaintainanceTool`
* Install desired version of Qt
* Select the following compiler targets:
  * Linux 64 Bit

#### Linux

* Qt is installed in /opt/Qt/
* Run `open MaintainanceTool.app`
* Install desired version of Qt
* Select the following compiler targets:
  * macOS

Once you have updated all agents, resume all builda gents.

## Step 2 - Update test code and make test build

* Update the `QT_VERSION` in `scripts-internal/build.sh`
* Update `SUPPORTED_VERS` in `build-linux.sh`
* Unpause build agents, and push to CI Server
* Ensure build goes as expected
* Test application

## Step 3 - Generate QT Symbols

* Create a tag `makeqtsyms-<something>` (ex `makeqtsyms-5128-1`)
* Running a build with tag `makeqtsyms-*` will run a separate script to generate Qt symbols
* Ensure builds go through on each platform and artifacts are created.
* Download all artifacts

## Step 4 - Set up symbols on crashlab

Copy all symbols into `crashlab/resources/qtsyms`. So for example, if you have downloaded the artifacts to `~/out/pia/artifacts`, you could do

* `cd ~/out/pia/artifacts/syms/5.12.8/win-x86`
* `cp -r * ~/crashlab/resources/qtsyms`

and copy all symbol files into crashlab repo, and create a commit. The `.sym` files should go in LFS

* `out/pia/artifacts/syms/5.12.8/win-x86`
* `out/pia/artifacts/syms/5.12.8/win-x64`
* `out/pia/artifacts/syms/5.12.8/linux-x64`
* `out/pia/artifacts/syms/5.12.8/mac`

Run the unit tests of crashlab to double check before deploy

```
$ ./vendor/bin/phpunit
PHPUnit 7.5.20 by Sebastian Bergmann and contributors.

...................................                               35 / 35 (100%)

Time: 3.75 seconds, Memory: 40.00 MB

OK (35 tests, 133 assertions)
```

And perform a deploy

`$ ./deploy.sh`

## Step 5 - Test end-to-end

Once you have deployed the new Qt symbols, create a test crash from the client, and submit a report. Ensure that Qt symbols show up in a crash report. Ensure you detect it for client and daemon crashes.

Note that if you aren't using a tagged build of the application, you will not see application symbols.
