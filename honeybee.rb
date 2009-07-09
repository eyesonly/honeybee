#!/usr/bin/env ruby

require 'time'
# require 'digest/md5'
require 'rubygems'
require 'ruby-debug'
require 'ruby-aes'
require 'resolv'

class Honeybee

  KEY_LENGTH = 256.freeze
  MODE = 'CBC'.freeze

  def initialize(block_secret, field_secret, iv_secret, spinner_key, a_secret)
    @block_secret   = block_secret
    @iv_secret      = iv_secret
    @spinner_secret = field_secret
    @spinner_key    = spinner_key
    @a_secret       = a_secret
    @lookup = Hash.new
  end

  def encrypt_form(time, ip, blog_id, form)

    @encform ||= Hash.new

    if time == nil
      time = Time.now
    end
    time = time.to_i

    # form = Hash[*form.collect { |v| [v, ""] }.flatten] if form.class == Array

    spinner = build_spinner(time, ip, blog_id)
    form[:spinner] = spinner
    form[:time]    = time
    form[:blog_id] = blog_id

    #All names are encrypted here, time and blog_id values are also AESd
    form.each do |n,v|
      new_n = convert_fieldname(n,spinner)

      if n == :time || n == :blog_id
        new_v = aes_encrypt(v)
      else
        new_v = v
      end

      # @encform.push(new_n, new_v)
      @encform[new_n] = new_v
      @lookup[n] = new_n

    end

     @spinner = spinner
     @encform
  end

  def n(symb)
     @lookup[symb]
  end

  def v(symb)
    new_n = @lookup[symb]
    new_n = @lookup[":" + symb.to_s] if new_n == nil
    return @encform[new_n]
  end

  def build_spinner(time, ip, blog_id)
    return digest_hash(time.to_s + ip.to_s + blog_id.to_s + @spinner_secret)
  end

  def digest_hash(str)
    a = Digest::MD5.hexdigest(str)
    # a = Digest::SHA256.hexdigest(str)
    return a[19,1] + a + a[16,1] #to pad it up to 66 chars from 64 TODO - remove?
  end

  def aes_encrypt(value)
    return Aes.encrypt_buffer(KEY_LENGTH, MODE, @block_secret, @iv_secret, value.to_s).unpack("H*").first
  end

  def aes_decrypt(v)
    vlen = v.size / 2
    binary_data = v.unpack('a2'*vlen).map{|x| x.hex}.pack('c'*vlen)
    Aes.decrypt_block(KEY_LENGTH, MODE, @block_secret, @iv_secret, binary_data).gsub(/t|\017|\006/, "")
  end

  def convert_fieldname(name,spinner)
    #Keys are digest.hashes of the real field name, the spinner, and a secret
    if name == :spinner
      #EXCEPT for the spinner itself, its key is AES encrypted using spinner_key
      new_name = Aes.encrypt_buffer(KEY_LENGTH, MODE, @spinner_key, @iv_secret, :spinner.to_s).unpack("H*").first
    else
      new_name = digest_hash(name.to_s + spinner + @a_secret)
    end

    return new_name
  end

  def validate_form(ip, secondsvalid, blog_id, form)
    @encform = form
    @spinner  = extract_spinner(ip)
    raise "Form submitted does not seem to come from current url" if @bval != blog_id
    timenow = Time.now.to_i
    raise "Form has expired"           if timenow - @tval.to_i > secondsvalid.to_i
    raise "Form comes from the future" if @tval.to_i > timenow
  end

  def check_honeypots(spambot)
    @lookup.each do |n,v|
      raise "Spambot check failure - ign" if n.to_s[0..5] == "ignore" && v(n) != ""
      raise "Spambot check failure - pot" if n.to_s[0..2] == "pot" && v(n) != nil
      raise "Spambot check failure - hon" if n.to_s[0..4] == "honey"  && v(n) != spambot
    end
  end

  def extract_spinner(ip)
    #determines where the spinner is in the encoded form, and validates if it is a valid digest hash of the
    #time,blog_id,ip,and spinner_secret
    spinner_candidate = @encform.detect do |n, v|
      nlen = n.size / 2
      binary_data = n.unpack('a2'*nlen).map{|x| x.hex}.pack('c'*nlen)
      true if :spinner.to_s == Aes.decrypt_block(KEY_LENGTH, MODE, @spinner_key, @iv_secret, binary_data).gsub("\t", "")
    end
    raise "Cannot decrypt form" if spinner_candidate == nil

    #find the time and blog_id fields using the spinner candidate
    @encform.each do |n, v|
       @tenc = v if n == digest_hash(:time.to_s    + spinner_candidate[1] + @a_secret)
       @benc = v if n == digest_hash(:blog_id.to_s + spinner_candidate[1] + @a_secret)
    end
    raise "Cannot find time/id fields on form" if @tenc == nil || @benc == nil

    #decrypt the time and blog_id values
    @tval = aes_decrypt(@tenc)
    @bval = aes_decrypt(@benc)

    #check spinner integrity
    @spinner = spinner_candidate[1] if spinner_candidate[1] ==  build_spinner(@tval, ip, @bval)
    raise "Spinner invalid" if !@spinner
    @spinner_name = spinner_candidate[0]
    @spinner
  end

  def decrypt_form(fieldlist)
    @lookup ||= Hash.new
    @lookup.clear
    fieldlist.push :time, :blog_id

    fieldlist.each do |n|
      new_name = digest_hash(n.to_sym.to_s + @spinner + @a_secret)
      @lookup[n] = new_name
    end

    @lookup[:spinner] = @spinner_name
  end

  def check_email(mode, email_field)
    regex = /^[a-zA-Z][\w\.-]*[a-zA-Z0-9]@[a-zA-Z0-9][\w\.-]*[a-zA-Z0-9]\.[a-zA-Z][a-zA-Z\.]*[a-zA-Z]$/
    email = v(email_field)
    raise "Email address appears to be invalid" if !email.match(regex)
    if mode == :full
      raise "Email domain seems to be invalid" if !validate_email_domain(email)
    end
  end

   def validate_email_domain(email)
      domain = email.match(/\@(.+)/)[1]
      Resolv::DNS.open do |dns|
          @mx = dns.getresources(domain, Resolv::DNS::Resource::IN::MX)
      end
      @mx.size > 0 ? true : false
end


end

if __FILE__ == $0
  # begin
    honey = Honeybee.new("lock_secretgsijghowi  afhfjsdfhs",  #32 chars long
                         "field_secretyadaydahdgaydaydgagd",  #32 chars long
                         "1234567890ABCDEF01234567890ABCDE",  #IV- 32 hex chars
                         "spinner_key_exactly_32_char_long",  #32 chars long
                         "a_secret")
    form = Hash.new
    form[:name] = 'name'
    form[:mail] = 'mail'
    form[:honey1] = 'dont enter a value here'
    form[:message] = 'rain in spain'
    # ip = `/sbin/ifconfig eth0 | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}'`
    ip = `/sbin/ifconfig en1 | grep 'netmask' /usr/bin/awk '{ print $2}'`
    blog_id = '2'
    newform = honey.encrypt_form(nil, ip, blog_id, form)
    honey.validate_form(ip, 3600, blog_id, newform)
    dec_form = honey.decrypt_form(%w(:name :mail :honey1 :message))
    puts dec_form
  # rescue Exception => e
  #   debugger
  #   puts e
  # end
end
