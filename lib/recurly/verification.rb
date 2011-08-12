module Recurly
  module Verification
    def digest_data(data) 
      if data.is_a? Array
        return nil if data.empty?
        '[%s]' % data.map{|v|digest_data(v)}.reject{|v|v.nil?}.join(',')
      elsif data.is_a? Hash
        digest_data Hash[data.sort].map {|k,v|
          prefix = (k =~ /\A\d+\Z/) ? '' : (k+':')
          (v=digest_data(v)).nil? ? nil : '%s%s' % [prefix,v]
        }
      else
        data
      end
    end

    def generate_signature(claim, args, timestamp=nil)
      raise Recurly::ConfigurationError.new("Recurly gem not configured. 'private_key' missing.") if Recurly.private_key.blank?

      timestamp ||= Time.now.to_i
      timestamp = timestamp.to_s
      input_data = [timestamp,claim,args]
      input_string = digest_data(input_data)

      pp input_string
      digest_key = ::Digest::SHA1.digest(Recurly.private_key)
      sha1_hash = ::OpenSSL::Digest::Digest.new("sha1")
      signature = ::OpenSSL::HMAC.hexdigest(sha1_hash, digest_key, input_string.to_s)
      signature + '-' + timestamp
    end

    def verify_params(claim, args)
      return false unless signature = args[:signature]
      signature = args.delete 'signature'
      hmac, timestamp = signature.split('-')
      age = Time.now.to_i - timestamp.to_i
      # return false if age > 3600 || age < 0
      signature == generate_signature(claim, args, timestamp)
    end

    def sign_billing_info_update(account_code)
      generate_signature(['billinginfoupdate', account_code])
    end

    def sign_transaction(account_code, currency, amount_in_cents)
      generate_signature(['transactioncreate', account_code, currency, amount_in_cents]) 
    end

    def verify_subscription(params)
      verify_params 'subscriptioncreated', params
    end

    def verify_transaction(params)
      verify_params 'transactioncreated', params
    end

    def verify_billing_info_update(params)
      verify_params 'billinginfoupdated', params
    end

    extend self
  end
end
