require "../bindata"

module ASN1; end

class BER < BinData; end

require "./asn1/identifier"
require "./asn1/length"
require "./asn1/data_types"

module ASN1
  class BER < BinData
    endian big

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

    def tag_number=(tag_type : Int | UniversalTags)
      @identifier.tag_number = tag_type.to_i.to_u8
    end

    def tag
      raise "only valid for universal tags" unless tag_class == TagClass::Universal
      UniversalTags.new tag_number.to_i
    end

    def extended?
      @identifier.extended? ? @identifier.extended : nil
    end

    def extended=(parts : Array(ExtendedIdentifier))
      @identifier.extended = parts
    end

    def extended
      @identifier.extended
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
        begin
          @payload = Bytes.new(@length.length)
          io.read_fully(@payload)
        rescue ArgumentError
          # Typically occurs if length is negative
          raise ArgumentError.new("invalid ASN.1 length: #{@length.length}")
        end
      end
      io
    end

    def write(io : IO)
      @length.length = @payload.size
      super(io)
      io.write(@payload)
      io.write_bytes(0_u16) if @length.indefinite?
      0_i64
    end

    # Check if this can be expanded into multiple sub-entries
    def sequence?
      return false unless tag_class == TagClass::Universal
      tag = UniversalTags.new tag_number.to_i
      constructed && {UniversalTags::Sequence, UniversalTags::Set}.includes?(tag)
    end

    # Extracts children from the payload
    def children
      parts = [] of BER
      io = IO::Memory.new(@payload)
      while io.pos < io.size
        parts << io.read_bytes(ASN1::BER)
      end
      parts
    end

    def children=(parts)
      self.constructed = true
      io = IO::Memory.new
      parts.each(&.write(io))
      @payload = io.to_slice
      parts
    end

    def inspect(io : IO) : Nil
      io << "#<" << {{@type.name.id.stringify}} << ":0x"
      object_id.to_s(io, 16)

      io << " tag_class="
      tag_class.to_s(io)
      io << " constructed="
      constructed.to_s(io)
      if tag_class == TagClass::Universal
        io << " tag="
        tag.to_s(io)
      end
      io << " tag_number="
      tag_number.to_s(io)
      io << " extended="
      @identifier.extended?.to_s(io)
      io << " size="
      size.to_s(io)
      io << " payload="
      @payload.inspect(io)

      io << ">"
      nil
    end
  end
end
