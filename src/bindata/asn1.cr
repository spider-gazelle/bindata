require "../bindata"

module ASN1; end

class BER < BinData; end

require "./asn1/identifier"
require "./asn1/length"

module ASN1
  class BER < BinData
    endian big

    enum UniversalTags
      EndOfContent
      Boolean
      Integer
      BitString
      OctetString
      Null
      ObjectIdentifier
      ObjectDescriptor
      External
      Float
      Enumerated
      EmbeddedPDV
      UTF8String
      RelativeOID
      Reserved1
      Reserved2
      Sequence
      Set
      NumericString
      PrintableString
      T61String
      VideotexString
      IA5String
      UTCTime
      GeneralizedTime
      GraphicString
      VisibleString
      GeneralString
      UniversalString
      CharacterString
      BMPString
    end

    # Components of a BER object
    custom identifier : Identifier = Identifier.new
    custom length : Length = Length.new
    property payload : Bytes = Bytes.new(0)

    def tag_class
      @identifier.tag_class
    end

    def tag_class=(tag : TagClass)
      @identifier.tag_class = tag
    end

    def constructed
      @identifier.constructed
    end

    def constructed=(custom : Bool)
      @identifier.constructed = custom
    end

    def tag_number
      @identifier.tag_number
    end

    def tag_number=(tag : Int | UniversalTags)
      @identifier.tag_number = 0b00011111_u8 & tag.to_i
    end

    def extended?
      @identifier.extended? ? @identifier.extended : nil
    end

    def extended=(parts : Array(ExtendedIdentifier))
      @identifier.extended = parts
    end

    def size
      @length.length
    end

    def read(io : IO) : IO
      super(io)
      if @length.indefinite?
        temp = IO::Memory.new
        # init to 1 as we need two 0 bytes to indicate end of stream
        previous_byte = 1_u8
        loop do
          current_byte = io.read_byte.not_nil!
          break if previous_byte == 0_u8 && current_byte == 0_u8
          temp.write_byte previous_byte
          previous_byte = current_byte
        end

        @payload = Bytes.new(temp.pos)
        temp.rewind
        temp.read_fully(@payload)
      else
        @payload = Bytes.new(@length.length)
        io.read_fully(@payload)
      end
      io
    end

    def write(io : IO) : IO
      @length.length = @payload.size
      super(io)
      io.write(@payload)
      io.write_bytes(0_u16) if @length.indefinite?
      io
    end
  end
end
