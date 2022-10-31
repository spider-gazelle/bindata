require "./helper"

describe BinData do
  it "should parse an object with an enum from an IO" do
    io = IO::Memory.new
    io.write_byte(0)
    io.write_bytes 2_u16, IO::ByteFormat::BigEndian
    io.write_byte(0)
    io.write_byte(0)
    io.rewind

    r = io.read_bytes(EnumData)
    r.start.should eq(0_u8)
    r.inputs.should eq(EnumData::Inputs::HDMI2)
    r.input.should eq(EnumData::Inputs::VGA)
    r.end.should eq(0_u8)
  end

  it "should write an object with an enum to an IO" do
    io = IO::Memory.new
    io.write_byte(0)
    io.write_bytes 1_u16, IO::ByteFormat::BigEndian
    io.write_byte(5)
    io.write_byte(0)
    io.rewind

    r = EnumData.new
    r.input = EnumData::Inputs::HDMI
    r.enabled = true
    io2 = IO::Memory.new
    r.write(io2)
    io2.rewind

    io2.to_slice.should eq(io.to_slice)
  end

  it "should work with differently types" do
    io = IO::Memory.new
    io.write_bytes 0x0111_u16, IO::ByteFormat::BigEndian
    io.rewind

    p = io.read_bytes(Packet)
    p.type.should eq(Packet::Type::Reply)
  end
end

class Packet < BinData
  endian big

  enum Type : UInt16
    Command = 0x0100
    Inquiry = 0x0110
    Reply   = 0x0111
  end

  enum_field UInt16, type : Type = Type::Command
end
