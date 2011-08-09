require 'spec_helper'

module Recurly
  describe Encryption do
    origin_time = 1312806801
    test_sig = '510eeb574ceb5f2a99c852d04286a134716e12eb-1312806801'

    before(:each) do
      Recurly.configure_from_yaml("#{File.dirname(__FILE__)}/../config/recurly.yml")
    end

    it "should generate proper signatures" do
      Time.stub!(:now).and_return(origin_time) # gen at origin time
      sig = Encryption.generate_signature(['foo','bar'])
      sig.should == test_sig
    end

    it "should validate proper signatures" do
      Time.stub!(:now).and_return(Time.at(origin_time+60)) # one minute passed
      sig = Encryption.verify_params(test_sig, ['foo','bar'])
      sig.should == true
    end

    it "should reject invalid signature" do
      Time.stub!(:now).and_return(Time.at(origin_time+60)) # one minute passed
      sig = Encryption.verify_params('badsig', ['foo','bar'])
      sig.should == false
    end

    it "should reject expired signature" do
      Time.stub!(:now).and_return(Time.at(origin_time+7200)) # two hours passed
      sig = Encryption.verify_params(test_sig, ['foo','bar'])
      sig.should == false
    end

    it "should reject time traveling signatures from the future" do
      Time.stub!(:now).and_return(Time.at(origin_time-60)) # one minute earlier
      sig = Encryption.verify_params(test_sig, ['foo','bar'])
      sig.should == false
    end
  end

end
