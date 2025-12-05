require_relative 'src/piactl.rb'
require_relative 'src/allowlan.rb'
require_relative 'src/nethelp.rb'
require_relative 'src/dnsleakchecker.rb'
require_relative 'src/retry.rb'
require_relative 'src/systemutil'

# "" is actually a valid value for overrideDNS
# and represents the "Use existing DNS" option
test_cases = [
    {dns: "pia", expected: ["10.0.0.243"], allowed_to_leak: false},
    {dns: "hdns", expected: ["103.196.38.38"], allowed_to_leak: true},
    {dns: ["1.1.1.1", "1.1.1.2"], expected: ["1.1.1.1", "1.1.1.2"], allowed_to_leak: true},
    {dns: ["127.0.0.1", "1.1.1.2"], expected: ["127.0.0.1", "1.1.1.2"], allowed_to_leak: true},
]
# Local DNS does not play nice with our windows and linux CI runners. Not worth to keep fighting it now, skip.
if !(SystemUtil.CI? && (SystemUtil.windows? || SystemUtil.linux?))
    test_cases << {dns: "", expected: :default_name_servers, allowed_to_leak: true}
end
# "Built-in Resolver" does not work in ubuntu. Skip for now, re-introduce if this gets fixed.
if !(SystemUtil.CI? && SystemUtil.linux?)
    test_cases << {dns: "local", expected: ["127.80.73.65"], allowed_to_leak: false} # Fun fact, this is 127.P.I.A
end

def any_in(array1, array2)
    matches = array1.select { |element| array2.include?(element) }
    !matches.empty?
end

test_cases.each do |test_case|
    describe "With DNS overriden to \"#{test_case[:dns]}\"" do
        # This is done only once, before any test is run
        before(:each) do
            # Start from a disconnected state
            @default_name_servers = NetHelp.default_nameservers
            PiaCtl.set_unstable("overrideDNS", test_case[:dns])
            test_case[:expected] = @default_name_servers if test_case[:expected] == :default_name_servers
        end

        describe "when disconnected from the VPN" do
            it "the default nameservers is unchanged from the system default" do
                current_nameservers = NetHelp.default_nameservers
                expect(any_in(current_nameservers, @default_name_servers)).to be_truthy
            end
        end

        describe "when connected to the VPN" do
            it "the default nameservers is any of #{test_case[:expected]}" do
                Retriable.run(attempts: 2, delay: 2) { PiaCtl.connect }
                current_nameservers = NetHelp.default_nameservers
                expect(any_in(test_case[:expected], current_nameservers)).to be_truthy, "Unexpected nameservers #{current_nameservers}"
            end

            if test_case[:allowed_to_leak]
                it "DNS requests can leak" do
                    expect {
                        Retriable.run(attempts: 4, delay: 0.5) { 
                            PiaCtl.disconnect
                            Retriable.run(attempts: 2, delay: 2) { PiaCtl.connect }
                            Retriable.run(attempts: 2, delay: 2) {DNSLeakChecker.dns_leaks?}
                        }
                    }.not_to raise_error
                end
            else
                it "DNS requests do not leak" do

                    leak_found = Retriable.run(attempts: 4, delay: 0.5, expect: false) { 
                        PiaCtl.disconnect
                        Retriable.run(attempts: 2, delay: 2) { PiaCtl.connect }
                        Retriable.run(attempts: 2, delay: 2, expect: false) { DNSLeakChecker.dns_leaks? }
                    }
                    expect(leak_found).to be_falsey, "Unexpected DNS leak detected"
                end
            end
        end
    end
end
