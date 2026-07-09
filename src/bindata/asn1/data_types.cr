require "big"
require "bit_array"

class ASN1::BER < BinData
  # The ASN.1 universal tag numbers, in tag-number order.
  enum UniversalTags
    EndOfContent
    Boolean
    Integer
    BitString   # Binary data
    OctetString # Hex values of the payload. Bytes[0x01, 0x02] == "0102"
    Null
    ObjectIdentifier # The tree like structure for objects 1.234.2.45.23 etc
    ObjectDescriptor
    External
    Float
    Enumerated
    EmbeddedPDV
    UTF8String
    RelativeOID
    Reserved1
    Reserved2
    Sequence # like a c-struct ordered list of objects
    Set      # set of objects no ordering
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
    CharacterString # Probably ASCII or UTF8
    BMPString
  end

  private def ensure_universal(check_tag)
    raise InvalidTag.new("not a universal tag: #{tag_class}") unless tag_class == TagClass::Universal
    raise InvalidTag.new("object is a #{tag}, expecting #{check_tag}") unless tag == check_tag
  end

  # Returns the object ID in string format.
  #
  # Sub-identifiers are decoded as big-endian base-128 numbers per X.690 §8.19
  # (every octet but the last has its high bit set), so arcs of any size are
  # supported. `BigInt` is used because OID arcs are unbounded (e.g. UUID-based
  # OIDs under `2.25`, ITU-T X.667).
  def get_object_id
    ensure_universal(UniversalTags::ObjectIdentifier)
    return "" if @payload.size == 0

    # Decode the payload into its base-128 sub-identifiers. This is BER-permissive
    # and does not reject non-minimal encodings (a leading 0x80 octet), which
    # X.690 §8.19.2 forbids for DER but which decode unambiguously.
    sub_ids = [] of BigInt
    value = BigInt.new(0)
    pending = false
    @payload.each do |byte|
      # A leading 0x80 starts a sub-identifier with a redundant zero septet.
      if @strict && !pending && byte == 0x80_u8
        raise ASN1::InvalidPayload.new("non-minimal OID sub-identifier in strict/DER mode")
      end
      value = value * 128 + (byte & 0x7f)
      pending = true
      if (byte & 0x80) == 0
        sub_ids << value
        value = BigInt.new(0)
        pending = false
      end
    end
    # A trailing continuation bit means the OID was truncated mid sub-identifier.
    raise InvalidObjectId.new(@payload.inspect) if pending

    # The first sub-identifier encodes the first two arcs: Y0 = 40 * X + Y,
    # with X capped at 2 (X = 2 absorbs any second arc, which may be large).
    first_sub = sub_ids.first
    if first_sub < 80
      arcs = [first_sub // 40, first_sub % 40]
    else
      arcs = [BigInt.new(2), first_sub - 80]
    end
    arcs.concat(sub_ids[1..])

    arcs.join(".")
  end

  # Sets a string representing an object ID.
  #
  # Each arc is encoded as a big-endian base-128 number per X.690 §8.19. Arcs
  # are parsed as `BigInt`, so arbitrarily large values are supported.
  def set_object_id(oid)
    # `BigInt.new` rejects non-numeric / empty arcs.
    arcs = begin
      oid.split(".").map { |part| BigInt.new(part) }
    rescue ArgumentError
      raise InvalidObjectId.new(oid)
    end

    # An OID has at least two arcs; a single-arc input used to be silently
    # expanded (`"2"` -> `"2.0"` on read), so reject it.
    raise InvalidObjectId.new(oid) if arcs.size < 2
    raise InvalidObjectId.new(oid) if arcs.any?(&.negative?)
    raise InvalidObjectId.new(oid) if arcs[0] > 2
    raise InvalidObjectId.new(oid) if arcs[0] < 2 && arcs[1] >= 40

    self.tag_class = TagClass::Universal
    self.tag_number = UniversalTags::ObjectIdentifier

    data = IO::Memory.new
    # The first two arcs are combined into a single sub-identifier.
    write_oid_sub_id(data, arcs[0] * 40 + arcs[1])
    arcs[2..].each { |arc| write_oid_sub_id(data, arc) }
    @payload = data.to_slice

    self
  end

  # Writes a single OID sub-identifier as a big-endian base-128 number, setting
  # the high (continuation) bit on every octet except the last.
  private def write_oid_sub_id(io : IO, value : BigInt) : Nil
    septets = [(value % 128).to_u8]
    value //= 128
    while value > 0
      septets << ((value % 128).to_u8 | 0x80_u8)
      value //= 128
    end
    septets.reverse_each { |byte| io.write_byte(byte) }
  end

  # Gets a hex representation of the bytes
  def get_hexstring(universal = true, tag = UniversalTags::OctetString)
    ensure_universal(tag) if universal
    @payload.hexstring
  end

  # Sets bytes from a hexstring
  def set_hexstring(string, tag = UniversalTags::OctetString, tag_class = TagClass::Universal)
    self.tag_class = tag_class
    self.tag_number = tag

    # Only a single leading `0x`/`0X` is stripped; everything else must already
    # be clean even-length hex. The old code stripped non-hex *anywhere* (merging
    # nibbles) and left-padded an odd length (shifting every nibble) — both
    # silent corruption. `hexbytes?` rejects odd length and stray characters.
    hex = string.lchop("0x").lchop("0X")
    @payload = hex.hexbytes? || raise ArgumentError.new("invalid hexstring: #{string.inspect}")
    self
  end

  # Returns the raw bytes
  def get_bytes
    @payload
  end

  # Sets the raw payload bytes and the given tag.
  def set_bytes(data, tag = UniversalTags::OctetString, tag_class = TagClass::Universal)
    self.tag_class = tag_class
    self.tag_number = tag

    # Copy so the payload doesn't alias (and track later mutations of) the
    # caller's buffer.
    @payload = data.to_slice.dup
    self
  end

  # String types whose repertoire is ASCII-compatible, so the UTF-8 `String.new`
  # decodes them directly. (T61String / VideotexString use the T.61 / videotex
  # character sets, which are neither ASCII nor UTF-8, so they are not decoded
  # here rather than mis-decoded.)
  DIRECT_STRING_TAGS = {
    UniversalTags::UTF8String, UniversalTags::CharacterString,
    UniversalTags::PrintableString, UniversalTags::IA5String,
    UniversalTags::OctetString, UniversalTags::NumericString,
    UniversalTags::VisibleString, UniversalTags::GeneralString,
    UniversalTags::GraphicString,
  }

  # Decodes the payload to a `String`. BMPString is transcoded from UTF-16BE and
  # UniversalString from UTF-32BE (leniently — surrogate pairs are accepted, not
  # strict UCS-2/UCS-4); the ASCII-repertoire types are read directly. An
  # incomplete/malformed byte sequence raises `ASN1::InvalidPayload`; individual
  # invalid code points may be substituted by the platform transcoder.
  def get_string
    raise InvalidTag.new("not a universal tag: #{tag_class}") unless tag_class == TagClass::Universal

    string = case tag
             when UniversalTags::BMPString
               decode_string("UTF-16BE")
             when UniversalTags::UniversalString
               decode_string("UTF-32BE")
             else
               raise InvalidTag.new("object is a #{tag}, not a supported string type") unless DIRECT_STRING_TAGS.includes?(tag)
               String.new(@payload)
             end

    # Reject an embedded NUL (a decoded character, not a raw byte — BMP/Universal
    # legitimately contain 0x00 bytes) to close CN-NUL injection.
    raise ASN1::InvalidPayload.new("embedded NUL in string (strict/DER mode)") if @strict && string.includes?('\0')
    string
  end

  private def decode_string(encoding : String) : String
    String.new(@payload, encoding)
  rescue ex : ArgumentError
    raise InvalidPayload.new("invalid #{encoding} string: #{ex.message}")
  end

  # Sets a string. BMPString is encoded to UTF-16BE and UniversalString to
  # UTF-32BE; every other type stores the string's UTF-8 bytes. *tag* may be a
  # `UniversalTags` or its integer value.
  def set_string(string, tag = UniversalTags::UTF8String, tag_class = TagClass::Universal)
    self.tag_class = tag_class
    self.tag_number = tag

    # Normalise so an integer tag (the accessor accepts `Int | UniversalTags`)
    # still selects the right transcoding rather than silently storing UTF-8.
    resolved = tag.is_a?(UniversalTags) ? tag : UniversalTags.new(tag.to_i)
    @payload = case resolved
               when UniversalTags::BMPString       then string.encode("UTF-16BE")
               when UniversalTags::UniversalString then string.encode("UTF-32BE")
               else                                     string.to_slice.dup
               end
    self
  end

  # `YYMMDDHHMM[SS](Z|±HHMM)` — the seconds are optional.
  UTCTIME_FORMAT = /\A(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{4})\z/
  # `YYYYMMDDHHMMSS(.fff)?(Z|±HHMM)`.
  GENERALIZEDTIME_FORMAT = /\A(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?(Z|[+-]\d{4})\z/

  # Reads the payload as a UTCTime or GeneralizedTime, normalised to UTC.
  #
  # A time zone is required (`Z` or a numeric `±HHMM` offset); a bare local time
  # is rejected. UTCTime's two-digit year uses the RFC 5280 pivot (`>= 50` =>
  # 19xx, `< 50` => 20xx).
  def get_time : Time
    raise InvalidTag.new("not a universal tag: #{tag_class}") unless tag_class == TagClass::Universal
    text = String.new(@payload)

    case tag
    when UniversalTags::UTCTime
      m = UTCTIME_FORMAT.match(text) || raise InvalidPayload.new("malformed UTCTime: #{text.inspect}")
      yy = m[1].to_i
      year = yy >= 50 ? 1900 + yy : 2000 + yy
      asn1_time_to_utc(year, m[2], m[3], m[4], m[5], m[6]?, nil, m[7])
    when UniversalTags::GeneralizedTime
      m = GENERALIZEDTIME_FORMAT.match(text) || raise InvalidPayload.new("malformed GeneralizedTime: #{text.inspect}")
      asn1_time_to_utc(m[1].to_i, m[2], m[3], m[4], m[5], m[6], m[7]?, m[8])
    else
      raise InvalidTag.new("object is a #{tag}, expecting UTCTime or GeneralizedTime")
    end
  end

  # Builds a UTC `Time` from decoded ASN.1 time components (strings), shifting a
  # numeric offset back to UTC. Raises `InvalidPayload` on out-of-range fields.
  private def asn1_time_to_utc(year : Int32, month, day, hour, minute, second, fraction, zone) : Time
    nanosecond = fraction ? (fraction.to_f * 1_000_000_000).to_i : 0
    wall = Time.utc(year, month.to_i, day.to_i, hour.to_i, minute.to_i,
      second ? second.to_i : 0, nanosecond: nanosecond)
    return wall if zone == "Z"

    off_hours = zone[1, 2].to_i
    off_minutes = zone[3, 2].to_i
    unless off_hours <= 23 && off_minutes <= 59
      raise InvalidPayload.new("time zone offset out of range: #{zone}")
    end
    offset = off_hours.hours + off_minutes.minutes
    zone[0] == '+' ? wall - offset : wall + offset
  rescue ex : ArgumentError
    raise InvalidPayload.new("invalid time components: #{ex.message}")
  end

  # Encodes *time* (converted to UTC) as a GeneralizedTime (default) or UTCTime,
  # in the canonical `…Z` form. UTCTime can only represent years 1950..2049.
  # Sub-second precision is dropped (DER forbids fractional seconds), so a `Time`
  # with a fractional part does not round-trip exactly through `#get_time`.
  def set_time(time : Time, tag = UniversalTags::GeneralizedTime)
    utc = time.to_utc
    text = case tag
           when UniversalTags::GeneralizedTime
             utc.to_s("%Y%m%d%H%M%SZ")
           when UniversalTags::UTCTime
             unless 1950 <= utc.year <= 2049
               raise InvalidPayload.new("UTCTime cannot represent year #{utc.year}; use GeneralizedTime")
             end
             utc.to_s("%y%m%d%H%M%SZ")
           else
             raise InvalidTag.new("set_time expects UTCTime or GeneralizedTime, got #{tag}")
           end

    self.tag_class = TagClass::Universal
    self.tag_number = tag
    @payload = text.to_slice
    self
  end

  # Reads the payload as a BOOLEAN.
  def get_boolean
    ensure_universal(UniversalTags::Boolean)
    raise InvalidPayload.new("empty BOOLEAN payload") if @payload.empty?
    if @strict && !(@payload.size == 1 && (@payload[0] == 0x00_u8 || @payload[0] == 0xFF_u8))
      raise ASN1::InvalidPayload.new("non-canonical BOOLEAN in strict/DER mode")
    end
    @payload[0] != 0_u8
  end

  # Sets a BOOLEAN payload.
  def set_boolean(value)
    self.tag_class = TagClass::Universal
    self.tag_number = UniversalTags::Boolean

    @payload = value ? Bytes[0xFF] : Bytes[0x0]
    self
  end

  # Whether this is a well-formed universal NULL element: primitive, tag `05`,
  # empty payload (X.690 §8.8).
  def null?
    tag_class == TagClass::Universal &&
      !constructed &&
      tag_number.to_i == UniversalTags::Null.to_i &&
      @payload.empty?
  end

  # Sets an empty, primitive NULL payload (encodes as `05 00`).
  def set_null
    self.tag_class = TagClass::Universal
    self.constructed = false
    self.tag_number = UniversalTags::Null

    @payload = Bytes.new(0)
    self
  end

  # Reads the payload as a two's-complement signed INTEGER (or ENUMERATED).
  #
  # With the default universal *check_class* the tag is validated against
  # *check_tags*. With a non-universal *check_class* (e.g. an SNMP context-tagged
  # Counter/Gauge) only the class is checked — the universal-tag check is skipped,
  # since `check_tags` are universal tags and don't apply to a context tag.
  def get_integer(check_tags = {UniversalTags::Integer, UniversalTags::Enumerated}, check_class = TagClass::Universal) : Int64
    raise InvalidTag.new("not a #{check_class} tag: #{tag_class}") unless tag_class == check_class
    if tag_class == TagClass::Universal
      raise InvalidTag.new("object is a #{tag}, expecting one of #{check_tags}") unless check_tags.includes?(tag)
    end
    ensure_minimal_integer if @strict
    return 0_i64 if @payload.size == 0

    # An INTEGER wider than 8 bytes cannot be represented in the Int64 this
    # returns; the bit-shift below would reach a shift count of 64+ (which is 0
    # in Crystal) and silently mis-decode. Reject it instead.
    raise InvalidPayload.new("INTEGER content of #{@payload.size} bytes exceeds Int64 range") if @payload.size > 8

    # Check if first bit is set indicating negativity
    negative = (@payload[0] & 0x80) > 0
    reverse_index = @payload.size - 1

    # initialize the result with the first byte
    start = if negative
              (~@payload[0]).to_i64 << (8 * reverse_index)
            else
              @payload[0].to_i64 << (8 * reverse_index)
            end

    # place the remaining bytes into the structure
    reverse_index -= 1
    @payload[1..-1].each do |byte|
      byte = ~byte if negative
      start += (byte.to_i64 << (reverse_index * 8))
      reverse_index -= 1
    end

    # `-start - 1`, not `-(start + 1)`: for Int64::MIN the magnitude `start`
    # reaches Int64::MAX, so `start + 1` would overflow before the negation.
    return -start - 1 if negative
    start
  end

  # Returns the INTEGER payload as raw bytes, with a leading zero/sign pad removed.
  # DER INTEGER: at least one content octet, and no redundant leading 0x00
  # (positive) / 0xFF (negative) octet.
  private def ensure_minimal_integer
    raise ASN1::InvalidPayload.new("empty INTEGER content in strict/DER mode") if @payload.empty?
    return if @payload.size < 2
    redundant = (@payload[0] == 0x00_u8 && (@payload[1] & 0x80) == 0) ||
                (@payload[0] == 0xFF_u8 && (@payload[1] & 0x80) != 0)
    raise ASN1::InvalidPayload.new("non-minimal INTEGER encoding in strict/DER mode") if redundant
  end

  def get_integer_bytes : Bytes
    ensure_universal(UniversalTags::Integer)
    ensure_minimal_integer if @strict
    return Bytes.new(0) if @payload.empty?

    # Unsigned magnitude only: a negative INTEGER (high bit of the first octet
    # set) has no meaningful magnitude here, so reject it rather than return
    # nonsense (it used to return Bytes[0] for -1).
    raise InvalidPayload.new("get_integer_bytes is only valid for a non-negative INTEGER") if (@payload[0] & 0x80) != 0

    # Drop leading 0x00 padding for the minimal magnitude, keeping one byte for 0.
    bytes = @payload
    while bytes.size > 1 && bytes[0] == 0_u8
      bytes = bytes[1..]
    end
    bytes
  end

  # Encodes *value* as a minimal two's-complement INTEGER payload.
  # ameba:disable Metrics/CyclomaticComplexity
  def set_integer(value, tag = UniversalTags::Integer, tag_class = TagClass::Universal)
    self.tag_class = tag_class
    self.tag_number = tag

    # extract the bytes from the value
    if value.responds_to?(:to_io)
      io = IO::Memory.new
      io.write_bytes value, IO::ByteFormat::BigEndian

      data = io.to_slice
      negative = value < 0
    else
      data = value.to_slice
      negative = false
    end

    # The bytes to write
    bytes = IO::Memory.new

    # Ignore padding bytes
    ignore = true
    if negative
      data.each do |byte|
        if ignore
          next if byte == 0xFF
          ignore = false
        end
        bytes.write_byte byte
      end
    else
      data.each do |byte|
        if ignore
          next if byte == 0x00
          ignore = false
        end
        bytes.write_byte byte
      end
    end

    # ensure there is at least one byte
    bytes.write_byte(negative ? 0xFF_u8 : 0x00_u8) if bytes.size == 0

    # Preserve the sign bit. A positive value whose top bit is set needs a 0x00
    # pad so it doesn't decode as negative; symmetrically, a negative value whose
    # top bit is clear needs a 0xFF pad so it doesn't decode as positive (e.g.
    # -129 is 0xFF 0x7F, not 0x7F). Without the negative pad, stripping the
    # leading 0xFF sign bytes above flips the sign.
    payload_bytes = bytes.to_slice
    pad = if !negative && (payload_bytes[0] & 0x80) > 0
            0x00_u8
          elsif negative && (payload_bytes[0] & 0x80) == 0
            0xFF_u8
          end
    if pad
      io = IO::Memory.new
      io.write_byte pad
      io.write payload_bytes
      payload_bytes = io.to_slice
    end

    @payload = payload_bytes
    self
  end

  # Reads the BIT STRING data bytes (dropping the leading unused-bit count). The
  # final byte's low `#bitstring_unused_bits` bits are padding. Any unused count
  # 0..7 is accepted; use `#get_bit_array` for the exact significant bits.
  def get_bitstring : Bytes
    ensure_bitstring
    @payload[1, @payload.size - 1]
  end

  # The number of unused (padding) bits in the final data byte (0..7).
  def bitstring_unused_bits : UInt8
    ensure_bitstring
    @payload[0]
  end

  private def ensure_bitstring
    ensure_universal(UniversalTags::BitString)
    raise InvalidPayload.new("empty BIT STRING payload") if @payload.empty?
    raise InvalidPayload.new("BIT STRING unused-bit count out of range: #{@payload[0]}") if @payload[0] > 7
    # With no data octets the unused-bit count must be 0 (else the significant
    # bit count would be negative).
    raise InvalidPayload.new("BIT STRING with no data must declare 0 unused bits") if @payload.size == 1 && @payload[0] != 0
  end

  # The BIT STRING's significant bits as a `BitArray`, numbered MSB-first from
  # the first data byte (ASN.1 bit 0 is the high bit of the first byte).
  def get_bit_array : BitArray
    data = get_bitstring
    total = data.size * 8 - bitstring_unused_bits
    arr = BitArray.new(total)
    total.times do |i|
      arr[i] = (data[i // 8] >> (7 - (i % 8))) & 1 == 1
    end
    arr
  end

  # Sets a BIT STRING from *bytes*, with *unused_bits* (0..7) of padding in the
  # final byte.
  def set_bitstring(bytes : Bytes, unused_bits : Int = 0)
    raise ArgumentError.new("unused_bits must be 0..7, got #{unused_bits}") unless 0 <= unused_bits <= 7
    raise ArgumentError.new("unused_bits must be 0 for an empty bit string") if bytes.empty? && unused_bits != 0

    self.tag_class = TagClass::Universal
    self.tag_number = UniversalTags::BitString

    payload = Bytes.new(bytes.size + 1)
    payload[0] = unused_bits.to_u8
    bytes.copy_to(payload + 1)
    @payload = payload
    self
  end

  # Sets a BIT STRING from a `BitArray` (numbered MSB-first, as ASN.1 expects).
  def set_bit_array(bits : BitArray)
    data = Bytes.new((bits.size + 7) // 8)
    bits.size.times do |i|
      data[i // 8] |= (0x80_u8 >> (i % 8)) if bits[i]
    end
    set_bitstring(data, data.size * 8 - bits.size)
  end
end
