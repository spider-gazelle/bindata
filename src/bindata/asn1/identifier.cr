class ASN1::BER < BinData
  # The class of an ASN.1 tag.
  enum TagClass
    Universal
    Application
    ContextSpecific
    Private
  end

  # One continuation byte of a high-tag-number (extended) identifier: a 7-bit
  # chunk of the tag number plus a `more` bit.
  class ExtendedIdentifier < BinData
    endian big

    bit_field do
      bool more, default: false
      bits 7, :tag_number
    end
  end

  # The leading identifier octet of a BER element (tag class, constructed flag and
  # tag number), plus any high-tag-number continuation bytes.
  class Identifier < BinData
    endian big

    # Cap on high-tag-number continuation bytes, to bound `read` against a stream
    # of `more`-flagged bytes (otherwise the array grows without limit). 16
    # base-128 bytes encode a tag number well beyond any real-world use.
    MAX_EXTENDED_BYTES = 16

    bit_field do
      bits 2, tag_class : TagClass = TagClass::Universal
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
          if @extended.size >= MAX_EXTENDED_BYTES
            raise InvalidTag.new("extended identifier exceeds #{MAX_EXTENDED_BYTES} bytes")
          end
          extended_id = begin
            io.read_bytes(ExtendedIdentifier)
          rescue IO::EOFError | BinData::ParseError
            # A `more`-flagged continuation with no following byte: report a typed
            # truncated-tag error. The continuation is a one-byte BinData bitfield,
            # so a read failure here is a truncated tag (EOF, wrapped as ParseError).
            raise InvalidTag.new("truncated extended identifier")
          end
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
