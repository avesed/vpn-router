require_relative 'src/piactl'
require_relative 'src/loadedlibchecker'
require_relative 'src/systemutil'

# Ensure that our main binaries do not load system versions of libraries we ship.
# This is mostly relevant in the case of libcrypto/ssl, which we ship and want to
# make sure we don't load newer/older versions present in the OS.
describe "Dependency loading" do
    describe "daemon" do
        it "doesn't load system libraries" do
            incorrectly_loaded_libs = LoadedLibChecker.find_incorrect_libs SystemUtil.os_choose("pia-service", "pia-daemon", "pia-daemon")
            expect(incorrectly_loaded_libs).to be_empty, "the libraries #{incorrectly_loaded_libs} should have been loaded from PIA install"
        end
    end

    describe "client" do
        it "doesn't load system libraries" do
            begin
                incorrectly_loaded_libs = LoadedLibChecker.find_incorrect_libs SystemUtil.os_choose("pia-client", "Private Internet Access", "pia-client")
                expect(incorrectly_loaded_libs).to be_empty, "the libraries #{incorrectly_loaded_libs} should have been loaded from PIA install"
            rescue ProcessNotFound => e
                # pia-client is optional because we cannot run it in CI
                skip e.message
            end
        end
    end

    describe "unbound" do
        it "doesn't load system libraries" do
            # Launch pia-unbound
            PiaCtl.set_unstable("overrideDNS", "local")
            PiaCtl.connect
            incorrectly_loaded_libs = LoadedLibChecker.find_incorrect_libs "pia-unbound"
            PiaCtl.disconnect
            PiaCtl.set_unstable("overrideDNS", "pia")

            expect(incorrectly_loaded_libs).to be_empty, "the libraries #{incorrectly_loaded_libs} should have been loaded from PIA install"
        end
    end
end
