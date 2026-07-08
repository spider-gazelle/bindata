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

    # `max_content_length` is inherited from `BinData`; reading the root
    # explicitly (rather than via `IO#read_bytes`) lets a cap be set before
    # parsing, and `#children` propagates it to nested elements.

    # Maximum nesting depth that `#children` will descend before raising
    # `MaxDepthExceeded`. The default (100) guards a recursive consumer walk
    # against stack overflow on a deeply nested message (a few KB of `30 80 …`
    # encodes thousands of levels); `0` disables the limit. Propagated to each
    # child alongside `max_content_length`.
    property max_depth : Int32 = 100

    # This element's depth in the parse tree (root = 0). Set by the parent's
    # `#children` so the limit is enforced relative to where parsing started.
    protected property depth : Int32 = 0

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
      n = tag_type.to_i
      # The identifier's tag-number field is 5 bits, so only 0..30 fit directly.
      # 31 (0b11111) is the reserved high-tag-number escape, and any value >= 31
      # requires the extended continuation-byte form, which this accessor does
      # not emit. Reject out-of-range values with a typed error rather than
      # silently truncating to 5 bits (50 -> 18) or leaking an `OverflowError`
      # from `to_u8` (>= 256). High-tag-number write support is tracked in #44.
      unless 0 <= n <= 30
        raise ASN1::InvalidTag.new("invalid tag number #{n}: must be 0..30 (high-tag-number form is not supported by tag_number=)")
      end
      @identifier.tag_number = n.to_u8
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

    # The current payload length in bytes. Reads from the payload itself (not the
    # decoded `Length`, which is only refreshed on `write`), so it is correct for
    # in-memory-built objects and for indefinite-length elements too.
    def size
      @payload.size
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
        # Fully qualified: `BinData::ContentTooLarge` (an ancestor constant) would
        # otherwise shadow this in BER's lexical scope, breaking the typed
        # `ASN1::Error` contract.
        raise ASN1::ContentTooLarge.new("ASN.1 content length #{size} exceeds max_content_length #{@max_content_length}")
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
    # `max_content_length` and `max_depth` caps propagate to each child.
    #
    # Only valid for a constructed element; on a primitive the payload is raw
    # content, not a TLV list, so parsing it would yield garbage. Raises
    # `ASN1::Error` in that case.
    def children
      unless constructed
        raise ASN1::Error.new("children is only valid for a constructed element")
      end

      # Refuse to descend past the limit, so a recursive consumer walk gets a
      # typed error instead of a stack overflow on a deeply nested message.
      if @max_depth > 0 && @depth >= @max_depth
        raise MaxDepthExceeded.new("ASN.1 nesting depth exceeds max_depth #{@max_depth}")
      end

      parts = [] of BER
      io = IO::Memory.new(@payload)
      while io.pos < io.size
        # Propagate the caps so a small frame can't smuggle an oversized or
        # over-deep child.
        child = BER.new
        child.max_content_length = @max_content_length
        child.max_depth = @max_depth
        child.depth = @depth + 1
        child.read(io)
        parts << child
      end
      parts
    end

    # Encodes *parts* into the payload and marks this element constructed. The
    # tag class/number are left untouched — set them yourself (e.g. to a universal
    # `Sequence`/`Set`, or a constructed context tag) so `#sequence?` reflects the
    # intended type; this accessor only guarantees the `constructed` flag.
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
