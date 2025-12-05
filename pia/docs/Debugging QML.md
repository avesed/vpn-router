# Debugging QML with GammaRay

GammaRay is a useful tool to debug QML elements at run-time.
It can be quite hard to debug UI statically from the code itself.

In order to use GammaRay, you will need to install Qt with these modules:  
`aqt install-qt mac desktop 6.2.4 --modules debug_info qtscxml qtshadertools`

## How to build GammaRay
* Build GammaRay v3.0.0 from [GammaRay Github repository](https://github.com/KDAB/GammaRay/tree/v3.0.0)
  * `git clone git@github.com:KDAB/GammaRay.git`
  * `git switch v3.0`
  * `mkdir build; cd build`
  * `cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=~/Qt6/6.2.4/clang_universal ..`
  * `cmake --build . --parallel`
  * `cmake --build . --target install`

## How to use GammaRay

### MacOS

* Launch GammaRay from /Applications
* Run the installed PIA client
* Attach GammaRay to PIA client
* Run `/Applications/GammaRay.app/Contents/MacOS/gammaray-client`
* Go to Quick Scenes
* In top central bar select DashboardWindow, PIA client preview should appear in the bottom left area
* Change a QML element property and verify the effect on the PIA client
