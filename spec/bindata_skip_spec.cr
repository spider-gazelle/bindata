require "./helper"

# Issue #4 — skip a run of bytes without storing them.
class WithSkip < BinData
  endian big

  field size : UInt8
  skip -> { size }
  field after : UInt8
end

describe "skip" do
  it "skips bytes on read and emits zero padding on write" do
    io = IO::Memory.new(Bytes[0x03, 0xFF, 0xFF, 0xFF, 0x42])
    obj = io.read_bytes(WithSkip)
    obj.size.should eq(0x03_u8)
    obj.after.should eq(0x42_u8)

    io2 = IO::Memory.new
    obj.write(io2)
    io2.to_slice.should eq(Bytes[0x03, 0x00, 0x00, 0x00, 0x42])
  end

  it "skips bytes from a streaming (non-sized) IO" do
    reader, writer = IO.pipe
    writer.write(Bytes[0x02, 0xEE, 0xEE, 0x09])
    writer.close

    obj = reader.read_bytes(WithSkip)
    obj.size.should eq(0x02_u8)
    obj.after.should eq(0x09_u8)
    reader.close
  end
end
