require "./helper"

describe BinData do
  it "should parse a complex object from an IO" do
    io = IO::Memory.new
    io.write_byte(0)
    io.write_bytes 5
    io.write "hello".to_slice
    io.write_byte(1)
    io.write_byte(3)
    io.write_byte(0)
    io.rewind

    r = Wow.new
    r.read io
    r.start.should eq(0_u8)
    r.head.size.should eq(5)
    r.head.name.should eq("hello")
    r.body.start.should eq(1_u8)
    r.body.end.should eq(3_u8)
    r.end.should eq(0_u8)
  end

  it "should parse a very complex object from an IO" do
    io = IO::Memory.new
    io.write_byte(0)
    io.write_bytes 0
    io.write_byte(0)
    io.rewind

    r = Wow.new
    r.read io
    r.start.should eq(0_u8)
    r.head.size.should eq(0)
    r.head.name.should eq("")
    r.body.start.should eq(0)
    r.body.end.should eq(0)
    r.end.should eq(0_u8)
  end

  it "should write a complex object to an IO" do
    io = IO::Memory.new
    io.write_byte(0)
    io.write_bytes 8
    io.write "whatwhat".to_slice
    io.write_byte(1)
    io.write_byte(3)
    io.write_byte(0)
    io.rewind

    r = Wow.new
    r.head = Header.new
    r.head.name = "whatwhat"

    io2 = IO::Memory.new
    r.write(io2)
    io2.rewind

    io2.to_slice.should eq(io.to_slice)
  end
end
