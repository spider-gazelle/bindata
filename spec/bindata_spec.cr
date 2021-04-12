require "./helper"

describe BinData do
  it "should parse an object from a Slice" do
    r = Header.new
    r.name = "foo"
    slice = r.to_slice
    Header.from_slice(slice).name.should eq "foo"
  end

  it "should parse an object from an IO" do
    io = IO::Memory.new
    io.write_bytes 5
    io.write "hello".to_slice
    io.rewind

    r = Header.new
    r.read io
    r.size.should eq(5)
    r.name.should eq("hello")
  end

  it "should write an object to an IO" do
    io = IO::Memory.new
    io.write_bytes 8
    io.write "whatwhat".to_slice
    io.rewind

    r = Header.new
    r.name = "whatwhat"

    io2 = IO::Memory.new
    r.write(io2)
    io2.rewind

    io2.to_slice.should eq(io.to_slice)
  end

  it "should allow mixed endianess" do
    io = IO::Memory.new
    io.write_bytes 0xBE_i16, IO::ByteFormat::BigEndian
    io.write_bytes 0xFEED_i32, IO::ByteFormat::LittleEndian
    io.write_bytes 0xDADFEDBEEF_i128, IO::ByteFormat::LittleEndian
    io.rewind

    r = MixedEndianLittle.new
    r.read io

    r.big.should eq(0xBE_i16)
    r.little.should eq(0xFEED_i32)
    r.default.should eq(0xDADFEDBEEF_i128)
  end
end
