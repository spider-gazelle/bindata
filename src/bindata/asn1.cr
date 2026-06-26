require "../bindata"

module ASN1; end

class BER < BinData; end

require "./asn1/exceptions"
require "./asn1/identifier"
require "./asn1/length"
require "./asn1/data_types"

module ASN1
  # A single ASN.1 Basic Encoding Rules (BER) TLV element: an identifier (tag),
  # a length and a payload. Used to build and parse SNMP, LDAP, X.509 and similar
  # protocols.
  #
  # ```
  # require "bindata/asn1"
  #
  # ber = ASN1::BER.new
  # ber.set_integer(42)
  # io.write_bytes(ber)
  #
  # ber = io.read_bytes(ASN1::BER)
  # ber.get_integer # => 42
  # ```
  #
  # Typed payload accessors live in `data_types.cr` (`get_integer`/`set_integer`,
  # `get_object_id`/`set_object_id`, `get_string`, `get_boolean`, ...). A
  # constructed element can be split into / built from sub-elements with
  # `#children` / `#children=`.
  class BER < BinData
    endian big

    # Components of a BER object
    field identifier : Identifier = Identifier.new
    field length : Length = Length.new
    property payload : Bytes = Bytes.new(0)

    # Maximum number of payload bytes this object (and its children) may
    # allocate or read. `0`, the default, means unlimited. Set a positive cap
    # before reading untrusted input to guard against allocation/exhaustion DoS,
    # reading the root explicitly so the cap is in place before parsing:
    #
    #     ber = ASN1::BER.new
    #     ber.max_content_length = 64 * 1024
    #     ber.read(io)
    property max_content_length : Int32 = 0

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

    # The universal tag as a `UniversalTags` enum. Raises unless this is a
    # universal-class element.
    def tag
      raise ASN1::InvalidTag.new("only valid for universal tags") unless tag_class == TagClass::Universal
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

    # The decoded payload length in bytes.
    def size
      @length.length
    end

    def read(io : IO) : IO
      super(io)
      if @length.indefinite?
        temp = IO::Memory.new
        # Read with one byte of look-ahead so the terminating `00 00` is detected
        # without being written into the payload. Seed with the first content byte
        # itself — seeding with a fake sentinel would prepend it to the payload.
        previous_byte = io.read_byte ||
                        raise ASN1::Error.new("unexpected end of input in indefinite-length BER content")
        loop do
          current_byte = io.read_byte ||
                         raise ASN1::Error.new("unexpected end of input in indefinite-length BER content")
          break if previous_byte == 0_u8 && current_byte == 0_u8
          temp.write_byte previous_byte
          ensure_content_length(temp.pos)
          previous_byte = current_byte
        end

        @payload = Bytes.new(temp.pos)
        temp.rewind
        temp.read_fully(@payload)
      else
        # Guard before allocating: the declared length is attacker-controlled.
        ensure_content_length(@length.length)
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

    private def ensure_content_length(size)
      return if @max_content_length <= 0
      if size > @max_content_length
        raise ContentTooLarge.new("ASN.1 content length #{size} exceeds max_content_length #{@max_content_length}")
      end
    end

    def write(io : IO)
      @length.length = @payload.size
      super(io)
      io.write(@payload)
      io.write_bytes(0_u16) if @length.indefinite?
      0_i64
    end

    # Whether this is a constructed universal Sequence or Set, i.e. an element
    # whose payload is itself a list of BER elements (see `#children`).
    def sequence?
      return false unless tag_class == TagClass::Universal
      tag = UniversalTags.new tag_number.to_i
      constructed && {UniversalTags::Sequence, UniversalTags::Set}.includes?(tag)
    end

    # Parses the payload as a sequence of nested BER elements. The
    # `max_content_length` cap propagates to each child.
    def children
      parts = [] of BER
      io = IO::Memory.new(@payload)
      while io.pos < io.size
        # Propagate the cap so a small frame can't smuggle an oversized child.
        child = BER.new
        child.max_content_length = @max_content_length
        child.read(io)
        parts << child
      end
      parts
    end

    # Encodes *parts* into the payload and marks this element constructed.
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
