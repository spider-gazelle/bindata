require "big"

class ASN1::BER < BinData
  class InvalidTag < Exception; end

  class InvalidObjectId < Exception; end

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

    raise InvalidObjectId.new(oid) if arcs.empty?
    raise InvalidObjectId.new(oid) if arcs.any?(&.negative?)
    raise InvalidObjectId.new(oid) if arcs[0] > 2
    raise InvalidObjectId.new(oid) if arcs.size > 1 && arcs[0] < 2 && arcs[1] >= 40

    self.tag_class = TagClass::Universal
    self.tag_number = UniversalTags::ObjectIdentifier

    data = IO::Memory.new
    if arcs.size > 1
      # The first two arcs are combined into a single sub-identifier.
      write_oid_sub_id(data, arcs[0] * 40 + arcs[1])
      arcs[2..].each { |arc| write_oid_sub_id(data, arc) }
    else
      write_oid_sub_id(data, arcs[0] * 40)
    end
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

    string = string.gsub(/(0x|[^0-9A-Fa-f])*/, "")
    string = "0#{string}" if string.size % 2 > 0
    @payload = string.hexbytes
    self
  end

  # Returns the raw bytes
  def get_bytes
    @payload
  end

  def set_bytes(data, tag = UniversalTags::OctetString, tag_class = TagClass::Universal)
    self.tag_class = tag_class
    self.tag_number = tag

    @payload = data.to_slice
    self
  end

  # Returns a UTF8 string
  def get_string
    check_tags = {UniversalTags::UTF8String, UniversalTags::CharacterString, UniversalTags::PrintableString, UniversalTags::IA5String, UniversalTags::OctetString}
    raise InvalidTag.new("not a universal tag: #{tag_class}") unless tag_class == TagClass::Universal
    raise InvalidTag.new("object is a #{tag}, expecting one of #{check_tags}") unless check_tags.includes?(tag)

    String.new(@payload)
  end

  # Sets a UTF8 string
  def set_string(string, tag = UniversalTags::UTF8String, tag_class = TagClass::Universal)
    self.tag_class = tag_class
    self.tag_number = tag

    @payload = string.to_slice
    self
  end

  def get_boolean
    ensure_universal(UniversalTags::Boolean)
    @payload[0] != 0_u8
  end

  def set_boolean(value)
    self.tag_class = TagClass::Universal
    self.tag_number = UniversalTags::Boolean

    @payload = value ? Bytes[0xFF] : Bytes[0x0]
    self
  end

  def get_integer(check_tags = {UniversalTags::Integer, UniversalTags::Enumerated}, check_class = TagClass::Universal) : Int64
    raise InvalidTag.new("not a universal tag: #{tag_class}") unless tag_class == check_class
    raise InvalidTag.new("object is a #{tag}, expecting one of #{check_tags}") unless check_tags.includes?(tag)
    return 0_i64 if @payload.size == 0

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

    return -(start + 1) if negative
    start
  end

  def get_integer_bytes : Bytes
    ensure_universal(UniversalTags::Integer)
    return Bytes.new(0) if @payload.size == 0
    return Bytes[0] if @payload.size == 1 && {0xFF_u8, 0_u8}.includes?(@payload[0])
    return @payload[1..-1] if @payload[0] == 0_u8
    @payload
  end

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

    # Make sure positive integers don't start with 0xFF
    payload_bytes = bytes.to_slice
    if !negative && (payload_bytes[0] & 0b10000000) > 0
      io = IO::Memory.new
      io.write_bytes 0x00_u8
      io.write payload_bytes
      payload_bytes = io.to_slice
    end

    @payload = payload_bytes
    self
  end

  def get_bitstring
    ensure_universal(UniversalTags::BitString)
    if @payload[0] == 0
      @payload[1, @payload.size - 1]
    else
      # skip = @payload[0]
      raise "skip not implemented"
    end
  end
end
