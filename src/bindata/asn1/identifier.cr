class ASN1::BER < BinData
  enum TagClass
    Universal
    Application
    ContextSpecific
    Private
  end

  class ExtendedIdentifier < BinData
    endian big

    bit_field do
      bool more, default: false
      bits 7, :tag_number
    end
  end

  class Identifier < BinData
    endian big

    bit_field do
      enum_bits 2, tag_class : TagClass = TagClass::Universal
      bool constructed, default: false
      bits 5, :tag_number
    end

    property extended : Array(ExtendedIdentifier) = [] of ExtendedIdentifier

    def extended?
      tag_class != TagClass::Universal && tag_number == 0b11111_u8
    end

    def read(io : IO) : IO
      super(io)
      if extended?
        @extended = [] of ExtendedIdentifier
        loop do
          extended_id = io.read_bytes(ExtendedIdentifier)
          @extended << extended_id
          break unless extended_id.more
        end
      end
      io
    end

    def write(io : IO)
      @tag_number = 0b11111_u8 if extended.size > 0
      super(io)
      extended.each_with_index do |ext, index|
        ext.more = (index + 1) < extended.size
        ext.write(io)
      end
      0_i64
    end
  end
end
