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

    if time == none
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



    end

  end

  def set_encform(encform)
    @encform = encform
  end

  def build_spinner(time, ip, blog_id)
    return Digest::MD5.hexdigest(time + ip + blog_id + @spinner_secret)
  end

  def aes_encrypt(value)
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

end

