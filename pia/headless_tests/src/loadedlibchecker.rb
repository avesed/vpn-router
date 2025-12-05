require_relative 'systemutil'

class LoadedLibChecker

    def self.find_incorrect_libs(process_name, min_lib_count=5)
        incorrectly_loaded_libs = []
        pia_libs = OS_PIA_LIBRARIES[SystemUtil.os]
        expected_prefix = SystemUtil.os_choose("C:\\Program Files\\Private Internet Access", "/Applications/Private Internet Access.app", "/opt/piavpn")
        loaded_libs = SystemUtil.loaded_libs process_name
        if loaded_libs.count < min_lib_count
            # We must expect some libraries to be loaded, otherwise there must be an issue somewhere
            raise "#{process_name} loaded too few libraries to consider it valid"
        end
        loaded_libs.each do |line|
            # Find which pia lib is represented in the line (if any)
            pia_lib = pia_libs.select { |lib| line.include? lib }
            # Find if the lib is loaded from pia's install dir
            loads_pia_lib = line.start_with?(expected_prefix)
            # If we loaded a pia_lib, but not from the install dir, it was incorrectly loaded
            if not pia_lib.empty? and not loads_pia_lib
                incorrectly_loaded_libs.append pia_lib[0]
            end
        end
        incorrectly_loaded_libs
    end

    OS_PIA_LIBRARIES = {
        # Windows libs exclude the .dll extension to consider any debug libs that end in `d.dll`
        :windows => [
            "kapps_regions",
            "kapps_core",
            "pia-commonlib",
            "kapps_net",
            "libcrypto-3-x64",
            "Qt6Core",
            "Qt6Network",
            "Qt6Xml",
            "qcertonlybackend",
            "qopensslbackend",
            "qschannelbackend",
            "pia-commonlib",
            "kapps_core",
            "kapps_regions",
            "Qt6QuickControls2",
            "pia-clientlib",
            "Qt6Qml",
            "Qt6QuickTemplates2",
            "Qt6Quick",
            "Qt6Gui",
            "Qt6QmlModels",
            "Qt6OpenGL",
            "qwindows",
            "workerscriptplugin",
            "Qt6QmlWorkerScript",
            "quickwindowplugin",
            "qtquickcontrols2plugin",
            "qtquickcontrols2basicstyleplugin",
            "qtquickcontrols2implplugin",
            "Qt6QuickControls2Impl",
            "qquicklayoutsplugin",
            "Qt6QuickLayouts",
            "pia-winrtsupport",
            "qgif",
            "qico",
            "qjpeg",
            "qsvg",
            "Qt6Svg",
            "qtquicktemplates2plugin",
            "qtlabsplatformplugin",
            "Qt6Widgets",
            "qmlshapesplugin",
            "Qt6QuickShapes"],
        :macos => [
            "libqsecuretransportbackend.dylib",
            "libqcertonlybackend.dylib",
            "libqopensslbackend.dylib",
            "libssl.3.dylib",
            "libcrypto.3.dylib",
            "kapps_core.3.6.0.dylib",
            "kapps_net.3.6.0.dylib",
            "kapps_regions.3.6.0.dylib",
            "pia-commonlib.3.6.0.dylib",
            "pia-clientlib.3.6.0.dylib",
            "libqcocoa.dylib",
            "libworkerscriptplugin.dylib",
            "libqtquickcontrols2plugin.dylib",
            "libquickwindowplugin.dylib",
            "libqtquickcontrols2basicstyleplugin.dylib",
            "libqgif.dylib",
            "libqquicklayoutsplugin.dylib",
            "libqicns.dylib",
            "libqico.dylib",
            "libqmacheif.dylib",
            "libqmacjp2.dylib",
            "libqsvg.dylib",
            "libqtga.dylib",
            "libqwbmp.dylib",
            "libqtquicktemplates2plugin.dylib",
            "libqjpeg.dylib",
            "libqtiff.dylib",
            "libqmlshapesplugin.dylib",
            "libqwebp.dylib",
            "libqtlabsplatformplugin.dylib"
        ],
        :linux => ["kapps_core.so",
            "kapps_net.so",
            "kapps_regions.so",
            "libcrypto.so",
            "libicui18n.so",
            "libQt6",
            "libQt6Core.so",
            "libQt6DBus.so",
            "libQt6Gui.so",
            "libQt6Network.so",
            "libQt6Qml.so",
            "libQt6QmlModels.so",
            "libQt6QmlWorkerScript.so",
            "libQt6Quick.so",
            "libQt6QuickControls2.so",
            "libQt6QuickShapes.so",
            "libQt6QuickTemplates2.so",
            "libQt6WaylandClient.so",
            "libQt6WaylandEglClientHwIntegration.so",
            "libQt6Widgets.so",
            "libQt6XcbQpa.so",
            "libssl.so",
            "libxcb-composite.so",
            "libxcb-damage.so",
            "libxcb-dpms.so",
            "libxcb-dri2.so",
            "libxcb-dri3.so",
            "libxcb-ewmh.so",
            "libxcb-glx.so",
            "libxcb-icccm.so",
            "libxcb-image.so",
            "libxcb-keysyms.so",
            "libxcb-present.so",
            "libxcb-randr.so",
            "libxcb-record.so",
            "libxcb-render-util.so",
            "libxcb-render.so",
            "libxcb-res.so",
            "libxcb-screensaver.so",
            "libxcb-shape.so",
            "libxcb-shm.so",
            "libxcb-sync.so",
            "libxcb-util.so",
            "libxcb-xf86dri.so",
            "libxcb-xfixes.so",
            "libxcb-xinerama.so",
            "libxcb-xinput.so",
            "libxcb-xkb.so",
            "libxcb-xtest.so",
            "libxcb-xv.so",
            "libxcb-xvmc.so",
            "libxcb.so",
            "pia-clientlib.so",
            "pia-commonlib.so"
        ]
    }

end