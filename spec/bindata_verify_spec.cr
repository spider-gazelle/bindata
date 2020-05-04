require "./helper"

describe BinData do
  it "succeeds reading when the verify proc is true" do
    io = IO::Memory.new
    io.write_byte 0x02
    io.write_byte 0x05
    io.write_byte 0x06
    io.write_byte 0x0B
    io.rewind

    r = io.read_bytes VerifyData
    r.checksum.should eq 0x0B
  end

  it "succeeds writing when the verify proc is true" do
    io = IO::Memory.new
    io.write_byte 0x02
    io.write_byte 0x05
    io.write_byte 0x06
    io.write_byte 0x0B
    io.rewind

    r = VerifyData.new
    r.size = 0x02
    r.bytes = Bytes.new 2
    r.bytes[0] = 0x05
    r.bytes[1] = 0x06
    r.checksum = 0x0B
    io2 = IO::Memory.new
    r.write io2
    io2.rewind

    io2.to_slice.should eq io.to_slice
  end

  it "raises an exception when it fails to verify on read" do
    io = IO::Memory.new
    io.write_byte 0x02
    io.write_byte 0x05
    io.write_byte 0x06
    io.write_byte 0xFF
    io.rewind

    expect_raises BinData::VerificationException, "Failed to verify reading basic at VerifyData.checksum" do
      io.read_bytes VerifyData
    end
  end

  it "raises an exception when it fails to verify on write" do
    io = IO::Memory.new
    io.write_byte 0x02
    io.write_byte 0x05
    io.write_byte 0x06
    io.write_byte 0x0B
    io.rewind

    r = io.read_bytes VerifyData
    r.bytes[0] = 0x0F
    io2 = IO::Memory.new

    expect_raises BinData::VerificationException, "Failed to verify writing basic at VerifyData.checksum" do
      r.write io2
    end
  end
end
