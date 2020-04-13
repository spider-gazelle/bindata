require "./helper"

describe BinData do
  it "should parse an inherited class object" do
    io = IO::Memory.new
    io.write_byte(0)
    io.write_bytes 2_u16, IO::ByteFormat::BigEndian
    io.write_byte(0)
    io.write_byte(0)
    io.write_byte(1)
    io.rewind

    r = io.read_bytes(Inherited)
    r.start.should eq(0_u8)
    r.inputs.should eq(Inherited::Inputs::HDMI2)
    r.input.should eq(Inherited::Inputs::VGA)
    r.end.should eq(0_u8)
    r.other_low.should eq(1_u8)
  end

  it "should write an inherited class to an IO" do
    io = IO::Memory.new
    io.write_byte(0)
    io.write_bytes 1_u16, IO::ByteFormat::BigEndian
    io.write_byte(13)
    io.write_byte(0)
    io.write_byte(1)
    io.rewind

    r = Inherited.new
    r.input = Inherited::Inputs::HDMI
    r.enabled = true
    r.reserved = 1_u8
    r.other_low = 1_u8
    io2 = IO::Memory.new
    r.write(io2)
    io2.rewind

    io2.to_slice.should eq(io.to_slice)
  end
end
