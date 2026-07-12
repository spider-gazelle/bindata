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

    # Maximum nesting depth that `#children` and the indefinite-length reader will
    # descend before raising `MaxDepthExceeded`. The default (100) guards both a
    # recursive consumer `#children` walk and the eager recursion of `#read` over
    # nested indefinite-length elements against stack overflow (a few KB of
    # `30 80 …` / `24 80 …` encodes thousands of levels); `0` disables the limit
    # (and with it the indefinite-read recursion bound). Propagated to each child
    # alongside `max_content_length`.
    property max_depth : Int32 = 100

    # This element's depth in the parse tree (root = 0). Set by the parent's
    # `#children` so the limit is enforced relative to where parsing started.
    protected property depth : Int32 = 0

    # When set, reject non-canonical (DER) encodings: non-minimal / indefinite
    # length, non-`{00,FF}` / multi-byte BOOLEAN, empty / non-minimal INTEGER,
    # non-minimal OID, embedded-NUL strings, and an out-of-order **universal**
    # SET OF (tag 17). Default `false` keeps the BER-permissive behaviour. Set it
    # before reading (the length checks fire during `read`), and it propagates to
    # `#children`.
    #
    # Not (yet) covered: an implicitly context-tagged SET OF (indistinguishable
    # from a SEQUENCE without a schema), GeneralizedTime/UTCTime canonical form,
    # BIT STRING padding bits, and the primitive-vs-constructed rule for strings.
    property? strict : Bool = false

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
      ensure_minimal_length if @strict
      if @length.indefinite?
        # Indefinite content is a sequence of complete TLV elements terminated by
        # an end-of-contents `00 00`. Walk them (rather than scanning for the first
        # `00 00`, which a `00 00` inside a nested element would trip) and store
        # their re-encoded bytes as the payload. This walk recurses into nested
        # indefinite elements, so it is bounded by `max_depth`.
        #
        # The payload is the children re-encoded, so the round-trip is byte-exact
        # for minimally-encoded content; a non-minimal inner length is normalised.
        if @max_depth > 0 && @depth >= @max_depth
          raise MaxDepthExceeded.new("ASN.1 nesting depth exceeds max_depth #{@max_depth}")
        end

        content = IO::Memory.new
        loop do
          child = BER.new
          child.max_content_length = @max_content_length
          child.max_depth = @max_depth
          child.depth = @depth + 1
          begin
            child.read(io)
          rescue ex : ASN1::Error
            raise ex
          rescue ex
            # A malformed / truncated element (not valid TLV) is rejected. The
            # original error is kept as the cause, so a transport `IO::Error` can
            # still be told apart from bad data.
            raise ASN1::Error.new("malformed indefinite-length BER content: #{ex.message}", ex)
          end
          break if child.eoc?
          child.write(content)
          ensure_content_length(content.pos)
        end

        @payload = content.to_slice
      else
        # Guard before allocating: the declared length is attacker-controlled.
        ensure_content_length(@length.length)
        begin
          @payload = Bytes.new(@length.length)
          io.read_fully(@payload)
        rescue ArgumentError
          # Defensive: `Length#read` already rejects negative / Int32-overflow
          # lengths with a typed `InvalidLength`, so a negative `@length.length`
          # cannot reach `Bytes.new` from the wire. Keep the guard, but raise a
          # typed `ASN1::InvalidLength` rather than leaking a bare `ArgumentError`.
          raise ASN1::InvalidLength.new("invalid ASN.1 length: #{@length.length}")
        end
      end
      io
    end

    # DER length rules (strict mode): definite form only, short form for 0..127,
    # and long form otherwise with no leading zero octets.
    private def ensure_minimal_length
      raise ASN1::InvalidLength.new("indefinite length is not allowed in strict/DER mode") if @length.indefinite?
      return unless @length.long
      raise ASN1::InvalidLength.new("non-minimal length: value #{@length.length} fits the short form") if @length.length <= 127
      raise ASN1::InvalidLength.new("non-minimal length: leading zero octet") if !@length.long_bytes.empty? && @length.long_bytes[0] == 0_u8
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

    # Whether this is an end-of-contents marker (`00 00`) — a primitive universal
    # EndOfContent element with an empty payload, used to terminate indefinite
    # content.
    def eoc?
      tag_class == TagClass::Universal &&
        !constructed &&
        tag_number.to_i == UniversalTags::EndOfContent.to_i &&
        @payload.empty?
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
    #
    # NOTE: this re-parses `@payload` on every call and returns a fresh array of
    # freshly-decoded children — it is not memoized (the payload is mutable, so a
    # cache would risk going stale). Bind the result to a local if you access the
    # children repeatedly on the same element.
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
        # Propagate the caps (and strict mode) so a small frame can't smuggle an
        # oversized / over-deep / non-canonical child.
        child = BER.new
        child.max_content_length = @max_content_length
        child.max_depth = @max_depth
        child.depth = @depth + 1
        child.strict = @strict
        child.read(io)
        parts << child
      end

      ensure_set_of_ordering(parts) if @strict && set?
      parts
    end

    # Whether this is a universal SET (used for the DER SET OF ordering rule).
    private def set?
      tag_class == TagClass::Universal &&
        tag_number.to_i == UniversalTags::Set.to_i
    end

    # DER SET OF: the elements must be sorted by their encoding.
    private def ensure_set_of_ordering(parts)
      encodings = parts.map(&.to_slice)
      encodings.each_cons_pair do |a, b|
        raise ASN1::Error.new("SET OF elements are not in canonical order") if (a <=> b) > 0
      end
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
