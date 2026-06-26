require "./helper"

describe ASN1 do
  it "should parse basic universal BER Objects" do
    io = IO::Memory.new(Bytes[2, 1, 1])
    ber = io.read_bytes(ASN1::BER)
    ber.inspect

    ber.tag_class.should eq(ASN1::BER::TagClass::Universal)
    ber.constructed.should eq(false)
    ber.tag_number.should eq(2)
    ber.extended?.should eq(nil)
    ber.size.should eq(1)
    ber.payload.should eq(Bytes[1])
  end

  it "should be able to write basic universal BER Objects" do
    goal = Bytes[2, 1, 1]
    ber = ASN1::BER.new
    ber.payload = Bytes[1]
    ber.tag_number = ASN1::BER::UniversalTags::Integer

    io = IO::Memory.new
    io.write_bytes(ber)
    io.rewind

    io.to_slice.should eq(goal)
  end

  it "should be able to read and write children" do
    b = Bytes[48, 129, 139, 2, 1, 0, 4, 11, 53, 114, 78, 84, 103, 33, 112, 109, 49, 99, 107, 164, 121, 6, 8, 43, 6, 1, 6, 3, 1, 1, 5, 64, 4, 10, 230, 254, 28, 2, 1, 3, 2, 1, 0, 67, 4, 14, 162, 200, 72, 48, 91, 48, 15, 6, 10, 43, 6, 1, 2, 1, 2, 2, 1, 1, 26, 2, 1, 26, 48, 35, 6, 10, 43, 6, 1, 2, 1, 2, 2, 1, 2, 26, 4, 21, 71, 105, 103, 97, 98, 105, 116, 69, 116, 104, 101, 114, 110, 101, 116, 49, 47, 48, 47, 49, 57, 48, 15, 6, 10, 43, 6, 1, 2, 1, 2, 2, 1, 3, 26, 2, 1, 6, 48, 18, 6, 12, 43, 6, 1, 4, 1, 9, 2, 2, 1, 1, 20, 26, 4, 2, 117, 112]
    io = IO::Memory.new(b)
    orig = io.read_bytes(ASN1::BER)
    children = orig.children
    children.size.should eq(3)

    io2 = IO::Memory.new
    ber = ASN1::BER.new
    ber.tag_number = ASN1::BER::UniversalTags::Sequence
    ber.children = children
    ber.write(io2)

    ber.size.should eq(orig.size)
    io2.to_slice.should eq(b)
  end

  it "should be able to read Object Identifiers" do
    b = Bytes[6, 8, 43, 6, 1, 6, 3, 1, 1, 5]
    io = IO::Memory.new(b)
    io.read_bytes(ASN1::BER).get_object_id.should eq("1.3.6.1.6.3.1.1.5")

    b = Bytes[6, 9, 0x2b, 6, 1, 4, 1, 0x82, 0x37, 0x15, 0x14]
    io = IO::Memory.new(b)
    io.read_bytes(ASN1::BER).get_object_id.should eq("1.3.6.1.4.1.311.21.20")
  end

  it "should be able to write Object Identifiers" do
    b = Bytes[6, 9, 0x2b, 6, 1, 4, 1, 0x82, 0x37, 0x15, 0x14]
    io = IO::Memory.new

    test = ASN1::BER.new
    test.set_object_id "1.3.6.1.4.1.311.21.20"
    test.tag.should eq(ASN1::BER::UniversalTags::ObjectIdentifier)

    io.write_bytes(test)
    io.to_slice.should eq(b)
  end

  it "should be able to read UTF8 strings" do
    b = Bytes[0x0c, 0x07, 0x63, 0x65, 0x72, 0x74, 0x72, 0x65, 0x71]
    io = IO::Memory.new(b)
    io.read_bytes(ASN1::BER).get_string.should eq("certreq")
  end

  it "should be able to write UTF8 strings" do
    b = Bytes[0x0c, 0x07, 0x63, 0x65, 0x72, 0x74, 0x72, 0x65, 0x71]

    io = IO::Memory.new
    test = ASN1::BER.new
    test.set_string "certreq"

    io.write_bytes(test)
    io.to_slice.should eq(b)
  end

  it "should be able to read Bools" do
    b = Bytes[0x01, 0x01, 0x0]
    io = IO::Memory.new(b)
    io.read_bytes(ASN1::BER).get_boolean.should eq(false)

    b = Bytes[0x01, 0x01, 0xFF]
    io = IO::Memory.new(b)
    io.read_bytes(ASN1::BER).get_boolean.should eq(true)
  end

  it "should be able to write Bools" do
    b = Bytes[0x01, 0x01, 0xFF]

    io = IO::Memory.new
    test = ASN1::BER.new
    test.set_boolean true

    io.write_bytes(test)
    io.to_slice.should eq(b)

    b = Bytes[0x01, 0x01, 0x00]

    io = IO::Memory.new
    test = ASN1::BER.new
    test.set_boolean false

    io.write_bytes(test)
    io.to_slice.should eq(b)
  end

  it "should be able to read Integers" do
    b = Bytes[0x02, 0x01, 0x5]
    io = IO::Memory.new(b)
    io.read_bytes(ASN1::BER).get_integer.should eq(5)

    b = Bytes[0x02, 0x02, 0x5, 0x0]
    io = IO::Memory.new(b)
    io.read_bytes(ASN1::BER).get_integer.should eq(0x500)

    b = Bytes[0x02, 0x01, 0xFB]
    io = IO::Memory.new(b)
    io.read_bytes(ASN1::BER).get_integer.should eq(-5)

    b = Bytes[0x02, 0x02, 0x00, 0xFB]
    io = IO::Memory.new(b)
    io.read_bytes(ASN1::BER).get_integer.should eq(0xFB)

    b = Bytes[0x02, 0x02, 0xFB, 0x00]
    io = IO::Memory.new(b)
    io.read_bytes(ASN1::BER).get_integer.should eq(-0x500)

    b = Bytes[0x02, 0x02, 0xFA, 0xFE]
    io = IO::Memory.new(b)
    io.read_bytes(ASN1::BER).get_integer.should eq(-0x502)
  end

  it "should be able to write Integers" do
    b = Bytes[0x02, 0x02, 0x5, 0x0]
    io = IO::Memory.new
    test = ASN1::BER.new
    test.set_integer 0x500
    io.write_bytes(test)
    io.to_slice.should eq(b)

    b = Bytes[0x02, 0x01, 0xFB]
    io = IO::Memory.new
    test = ASN1::BER.new
    test.set_integer -5
    io.write_bytes(test)
    io.to_slice.should eq(b)

    b = Bytes[0x02, 0x02, 0xFB, 0x00]
    io = IO::Memory.new
    test = ASN1::BER.new
    test.set_integer -0x500
    io.write_bytes(test)
    io.to_slice.should eq(b)

    b = Bytes[0x02, 0x02, 0xFA, 0xFE]
    io = IO::Memory.new
    test = ASN1::BER.new
    test.set_integer -0x502
    io.write_bytes(test)
    io.to_slice.should eq(b)

    # Positive integers can't start with 0xff
    b = Bytes[0x02, 0x03, 0, 255, 227]
    io = IO::Memory.new
    test = ASN1::BER.new
    test.set_integer 65507
    io.write_bytes(test)
    io.to_slice.should eq(b)
  end

  it "should be able to get a Bitstring" do
    b = Bytes[0x03, 0x02, 0x0, 0x1]
    io = IO::Memory.new(b)
    io.read_bytes(ASN1::BER).get_bitstring.should eq(Bytes[0x1])

    # Not implemented:
    # b = Bytes[0x03, 0x02, 0x4, 0x0, 0xF0]
    # io = IO::Memory.new(b)
    # io.read_bytes(ASN1::BER).get_bitstring.should eq(Bytes[0x0, 0xF])
  end

  # --- Object Identifier: base-128 multi-byte sub-identifiers (X.690 §8.19) ---
  # Audit Tier 0.1 / 0.2 — large arcs were silently corrupted / overflowed.

  it "writes an OID whose arc needs 3 base-128 bytes (RSA: 1.2.840.113549.1.1.1)" do
    # 42=0x2a ; 840=0x86 0x48 ; 113549=0x86 0xf7 0x0d ; 1 1 1
    goal = Bytes[6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1]
    test = ASN1::BER.new
    test.set_object_id "1.2.840.113549.1.1.1"

    io = IO::Memory.new
    io.write_bytes(test)
    io.to_slice.should eq(goal)
  end

  it "reads an OID whose arc needs 3 base-128 bytes (RSA: 1.2.840.113549.1.1.1)" do
    b = Bytes[6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1]
    io = IO::Memory.new(b)
    io.read_bytes(ASN1::BER).get_object_id.should eq("1.2.840.113549.1.1.1")
  end

  it "round-trips a large first sub-identifier under joint-iso-itu-t (2.999.3)" do
    # first=2, second=999 -> Y0 = 40*2 + 999 = 1079 = 0x88 0x37
    goal = Bytes[6, 3, 0x88, 0x37, 3]
    test = ASN1::BER.new
    test.set_object_id "2.999.3"

    io = IO::Memory.new
    io.write_bytes(test)
    io.to_slice.should eq(goal)

    io.rewind
    io.read_bytes(ASN1::BER).get_object_id.should eq("2.999.3")
  end

  it "round-trips an arc larger than UInt64 (UUID-based OID, ITU-T X.667)" do
    oid = "2.25.340282366920938463463374607431768211455" # 2.25.(2**128 - 1)
    test = ASN1::BER.new
    test.set_object_id oid

    io = IO::Memory.new
    io.write_bytes(test)
    io.rewind
    io.read_bytes(ASN1::BER).get_object_id.should eq(oid)
  end

  it "round-trips the first-sub-identifier boundary arcs (X = 0/1/2)" do
    {
      "1.39" => Bytes[6, 1, 0x4f],       # 40 + 39 = 79
      "2.0"  => Bytes[6, 1, 0x50],       # 80
      "2.47" => Bytes[6, 1, 0x7f],       # 80 + 47 = 127, last single-octet value
      "2.48" => Bytes[6, 2, 0x81, 0x00], # 128, first value needing two octets
    }.each do |oid, goal|
      test = ASN1::BER.new
      test.set_object_id oid
      io = IO::Memory.new
      io.write_bytes(test)
      io.to_slice.should eq(goal)

      io.rewind
      io.read_bytes(ASN1::BER).get_object_id.should eq(oid)
    end
  end

  it "reads an empty object identifier payload as an empty string" do
    io = IO::Memory.new(Bytes[6, 0])
    io.read_bytes(ASN1::BER).get_object_id.should eq("")
  end

  it "rejects malformed object identifiers" do
    expect_raises(ASN1::BER::InvalidObjectId) { ASN1::BER.new.set_object_id("3.1.1") } # first arc > 2
    expect_raises(ASN1::BER::InvalidObjectId) { ASN1::BER.new.set_object_id("0.40") }  # first < 2, second >= 40
    expect_raises(ASN1::BER::InvalidObjectId) { ASN1::BER.new.set_object_id("1.40") }  # first < 2, second >= 40
    expect_raises(ASN1::BER::InvalidObjectId) { ASN1::BER.new.set_object_id("1.-1") }  # negative arc
    expect_raises(ASN1::BER::InvalidObjectId) { ASN1::BER.new.set_object_id("1.x") }   # non-numeric arc
  end

  it "rejects a payload truncated mid sub-identifier (trailing continuation bit)" do
    # 0x2a decodes fine (42), 0x86 sets the continuation bit but no octet follows.
    io = IO::Memory.new(Bytes[6, 2, 0x2a, 0x86])
    expect_raises(ASN1::BER::InvalidObjectId) { io.read_bytes(ASN1::BER).get_object_id }
  end
end
