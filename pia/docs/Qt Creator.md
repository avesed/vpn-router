### Qt Creator

To open the project in Qt Creator, open CMakeLists.txt as a project.  This CMake script defines targets for Qt Creator and hooks them up to the appropriate rake tasks, which allows Qt Creator to build, run, and debug targets.
Run `rake stage` before this operation, otherwise CMake will fail.

Some specific configuration changes are useful in Qt Creator:

#### File Locator

The file locator (Ctrl+K / Cmd+K) can only locate files referenced by targets by default, so it won't be able to find build system files (.rb), scripts (.sh/.bat), etc.  To find any file in the project directory:

1. Open Qt Creator's Preferences
2. Go to Environment > Locator
3. Next to "Files in All Project Directories", check the box for "Default"
4. Select "Files in All Project Directoreis" and click "Edit..."
5. Add the exclusion pattern "*/out/*" (to exclude build outputs)

#### Default Target

Qt Creator's default target is 'all', which is hooked up to rake's default - the staged installation only.  (The real 'all' target takes a long time since it builds all tests, installers, tools, etc.)

To run or debug unit tests and other targets from Qt Creator, tell it to build the current executable's target instead:

1. Go to the Projects page
2. Select "Build" under current kit"
3. Under "Build Steps", expand the CMake build step
4. Select "Current executable" instead of "all":

#### Kit and Qt version

Qt Creator will still ask to select a kit, which includes a Qt version, compiler, etc.  Just select Qt 6.2.4 (on Windows, the MSVC 2019 64-bit target), so the code model will work.

This has no effect on the build output - the Rake scripts find Qt and the compiler on their own, which allows them to be run with no prior setup.

