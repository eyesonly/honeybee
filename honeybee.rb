#!/usr/bin/env ruby

require 'time'
require 'digest/md5'

class Honeybee
  def initialize(block_secret, field_secret, iv_secret, spinner_key, a_secret)
    @block_secret   = block_secret
    @iv_secret      = iv_secret
    @spinner_secret = field_secret
    @spinner_key    = spinner_key
    @a_secret       = a_secret
  end

  def prepare_form(time, ip, blog_id, *form)

    if time == nil
      time = Time.now
    end

    spinner = build_spinner(time, ip, blog_id)
    form << { :spinner => spinner }
    form << { :time => time }
    form << { :blog_id => blog_id }

    #All names are encrypted here, time and blog_id values are also AESd
    form.each do |n,v|

      new_n = convert_fieldname(n,spinner)
      if k == :time || k == :blog_id
        new_v = aes_encrypt(v)
      else
        new_v = v
      end

      newform << { new_n => new_v }

    end

     @spinner = spinner
     newform
  end

  def set_encform(encform)
    @encform = encform
  end

  def build_spinner(time, ip, blog_id)
    return Digest::MD5.hexdigest(time + ip + blog_id + @spinner_secret)
  end

  def aes_encrypt(value)
    return Aes.encrypt_block(KEY_LENGTH, MODE, @block_secret, @iv_secret, value)
  end

  def convert_fieldname(name,spinner)
    #Keys are hashes of the real field name, the spinner, and a secret

    if name == :spinner
      #EXCEPT for the spinner itself, its key is AES encrypted using spinner_key
      new_name = Aes.encrypt_block(KEY_LENGTH, MODE, @spinner_key, @iv_secret, :spinner)
    else
      new_name = Digest::MD5.hexdigest(name + spinner + @a_secret)
    end

    return new_name
  end

  def spinner_valid?(ip)
    #determines where the spinner is in the encoded form,
    #and validates if it is a valid MD5 hash of the
    #time,blog_id,ip,and spinner_secret
    #Will also set @spinner if a valid spinner is found

    spinner_candidate = @enc_form.detect { |n, v| v if :spinner == Aes.decrypt_block(KEY_LENGTH, MODE, @spinner_key, @iv_secret, n) }
    #   if :spinner == Aes.decrypt_block(KEY_LENGTH, MODE, @spinner_key, @iv_secret, n)
    #     spinner_candidate = v
    #   end
    # end
    return false if spinner_candidate == nil

    # @enc_form.each do |n, v|
    #   case get_fieldname(n)
    #     case
    #   end
    # end


    #find the time and blog_id fields

  end

end

