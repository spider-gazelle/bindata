class ASN1::BER < BinData
  class Length < BinData
    endian big

    bit_field do
      bool long, default: false
      bits 7, :length_indicator
    end

    array long_bytes : UInt8, length: ->{
      if long && !indefinite?
        0 | length_indicator
      else
        0
      end
    }

    # We can pretty much safely assume no protocol is implementing
    # more than positive Int32 datagrams
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
          @length = @length | (byte << (index * 8))
        end
      else
        @length = 0 | length_indicator
      end
      io
    end

    def write(io : IO) : IO
      long = true if @length >= 127

      if indefinite?
        @long_bytes = [] of UInt8
      elsif long
        @long_bytes = [] of UInt8
        io = IO::Memory.new(4)
        io.write_bytes @length, IO::ByteFormat::BigEndian

        skip = true
        io.to_slice.each do |byte|
          if skip && byte == 0
            next
          else
            skip = false
            @long_bytes << byte
          end
        end

        @length_indicator = 0_u8 | long_bytes.size
      else
        @length_indicator = 0_u8 | @length
        @long_bytes = [] of UInt8
      end

      super(io)
    end
  end
end
