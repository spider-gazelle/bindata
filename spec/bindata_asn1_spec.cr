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
end
