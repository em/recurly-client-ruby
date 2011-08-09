module Recurly
  class Encryption
    # encode a string using the configured private key
    def self.generate_signature(args, timestamp=nil)
      raise Recurly::ConfigurationError.new("Recurly gem not configured. 'private_key' missing.") if Recurly.private_key.blank?

      timestamp ||= Time.now.to_i
      timestamp = timestamp.to_s
      input_string = args.join() + timestamp
      digest_key = ::Digest::SHA1.digest(Recurly.private_key)
      sha1_hash = ::OpenSSL::Digest::Digest.new("sha1")
      signature = ::OpenSSL::HMAC.hexdigest(sha1_hash, digest_key, input_string.to_s)
      signature + '-' + timestamp
    end

    def self.verify_params(signature, args)
      hmac, timestamp = signature.split('-')
      age = Time.now.to_i - timestamp.to_i
      return false if age > 3600 || age < 0
      signature == generate_signature(args, timestamp)
    end

    def self.sign_billing_info_update(account_code)
      generate_signature('billinginfoupdate', account_code)
    end

    def self.sign_transaction(account_code, currency, amount_in_cents)
      generate_signature('transactioncreate', account_code, currency, amount_in_cents) 
    end

    def self.verify_subscription(account_code, plan_code, add_on_codes, coupon_code)
      verify_params('subscriptioncreated', account_code, plan_code, add_on_codes, coupon_code) 
    end

    def self.verify_transaction(account_code, currency, amount_in_cents, uuid)
      verify_params('transactioncreated', account_code, currency, amount_in_cents, uuid) 
    end

    def self.verify_billing_info_update(account_code)
      verify_params('billinginfoupdated', account_code) 
    end
  end
end

