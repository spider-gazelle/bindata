require "./helper"

describe ASN1 do
  it "should parse basic universal BER Objects" do
    io = IO::Memory.new(Bytes[2, 1, 1])
    ber = io.read_bytes(ASN1::BER)

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
end
