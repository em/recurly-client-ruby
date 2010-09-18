require 'spec_helper'

module Recurly
  describe Account do

    describe "#create" do

      around(:each) do |example|
        VCR.use_cassette('account/create', &example)
      end

      before(:each) do
        @account = Factory.create_account('account-create')
      end

      it "should have a created_at date" do
        @account.created_at.should_not be_nil
      end
    end

    describe "#find" do

      around(:each) do |example|
        VCR.use_cassette('account/find', &example)
      end

      let(:orig){ Factory.create_account("account-get") }

      before(:each) do
        @account = Account.find(orig.account_code)
      end

      it "should return the account object" do
        @account.should_not be_nil
      end

      describe "returned account" do
        it "should have a created_at date" do
          @account.created_at.should_not be_nil
        end

        it "should match the original account code" do
          @account.account_code.should == orig.account_code
        end

        it "should match the original account email" do
          @account.email.should == orig.email
        end

        it "should match the original first name" do
          @account.first_name.should == orig.first_name
        end
      end
    end

    describe "#update" do

      around(:each) do |example|
        VCR.use_cassette('account/update', &example)
      end

      let(:orig){ Factory.create_account("account-update") }

      before(:each) do
        # update account data
        @account = Account.find(orig.account_code)
        @account.last_name = "Update Test"
        @account.company_name = "Recurly Ruby Gem -- Update"
        @account.save

        # refetch account
        @account = Account.find(orig.account_code)
      end

      it "should not have updated the email address" do
        @account.email.should == orig.email
      end

      it "should have updated the last_name" do
        @account.last_name.should == "Update Test"
      end

      it "should have updated the company_name" do
        @account.company_name.should == "Recurly Ruby Gem -- Update"
      end
    end

    describe "#close_account" do
      around(:each) do |example|
        VCR.use_cassette('account/close', &example)
      end

      before(:each) do
        @account = Factory.create_account('account-close')
      end

      it "should run without errors" do
        @account.close_account
      end
    end

  end
end