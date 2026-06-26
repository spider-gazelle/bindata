class ASN1::BER < BinData
  # The length octets of a BER element: short form, long form, or the indefinite
  # marker. The decoded byte count is exposed as `#length`.
  class Length < BinData
    endian big

    bit_field do
      bool long, default: false
      bits 7, :length_indicator
    end

    field long_bytes : Array(UInt8), length: -> {
      if long && !indefinite?
        raise "invalid ASN.1 BER length. Number of length bytes: #{length_indicator}" if length_indicator > 4
        0 | length_indicator
      else
        0
      end
    }

    # We can pretty much safely assume no protocol is implementing
    # more than positive Int32 length datagrams
    property length : Int32 = 0

    def indefinite?
      long && length_indicator == 0_u8
    end

    def read(io : IO) : IO
      super(io)

      # set length field
      if indefinite?
        @length = 0
      elsif long
        @length = 0
        long_bytes.reverse.each_with_index do |byte, index|
          @length = @length | (byte.to_i32 << (index * 8))
        end
        # A 4-byte length with the high bit set overflows the Int32 we store it
        # in, surfacing as a negative value; reject it rather than misread it.
        raise InvalidLength.new("ASN.1 length exceeds Int32 maximum") if @length < 0
      else
        @length = length_indicator.to_i32
      end
      io
    end

    def write(io : IO)
      # Lengths 0..127 fit in short form; only 128+ need long form.
      self.long = true if @length > 127

      if long
        @long_bytes = [] of UInt8
        temp_io = IO::Memory.new(4)
        temp_io.write_bytes @length, IO::ByteFormat::BigEndian

        skip = true
        temp_io.to_slice.each do |byte|
          if skip && byte == 0
            next
          else
            skip = false
            @long_bytes << byte
          end
        end

        @length_indicator = @long_bytes.size.to_u8
      else
        @length_indicator = @length.to_u8
        @long_bytes = [] of UInt8
      end

      super(io)
      0_i64
    end
  end
end
