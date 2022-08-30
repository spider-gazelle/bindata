require "./helper"

describe BinData do
  it "reads the remaining bytes into Bytes" do
    io = IO::Memory.new
    io.write_byte 0x02
    rest = Bytes.new 4, &.to_u8
    io.write rest
    io.rewind

    r = io.read_bytes RemainingBytesData
    r.first.should eq 0x02
    r.rest.should eq rest
  end

  it "reads the remaining bytes into empty Bytes if none remain" do
    io = IO::Memory.new
    io.write_byte 0x02
    io.write Bytes.new 0
    io.rewind

    r = io.read_bytes RemainingBytesData
    r.first.should eq 0x02
    r.rest.size.should eq 0
  end

  it "reads the rest even if io has already been partially read" do
    io = IO::Memory.new
    io.write Bytes.new 10
    io.write_byte 0x02
    rest = Bytes.new 4, &.to_u8
    io.write rest
    io.rewind

    io.read Bytes.new 10
    r = io.read_bytes RemainingBytesData
    r.first.should eq 0x02
    r.rest.should eq rest
  end

  it "runs verification as expected" do
    io = IO::Memory.new
    io.write_byte 0x02
    io.write Bytes.new 15
    io.rewind

    ex = expect_raises BinData::ReadingVerificationException, "Failed to verify reading bytes at RemainingBytesData.rest" do
      io.read_bytes RemainingBytesData
    end
    ex.klass.should eq("RemainingBytesData")
    ex.field.should eq("rest")
    ex.field_type.should eq("bytes")
  end

  it "runs verification as expected while writing" do
    r = RemainingBytesData.new
    r.first = 0x02
    r.rest = Bytes.new 15
    io2 = IO::Memory.new

    ex = expect_raises BinData::WritingVerificationException, "Failed to verify writing bytes at RemainingBytesData.rest" do
      r.write io2
    end
    ex.klass.should eq("RemainingBytesData")
    ex.field.should eq("rest")
    ex.field_type.should eq("bytes")
  end

  it "abides by onlyif as expected" do
    io = IO::Memory.new
    io.write_byte 0x01
    io.write Bytes.new 4
    io.rewind

    r = io.read_bytes RemainingBytesData
    r.first.should eq 0x01
    r.rest.size.should eq 0
    io.pos.should eq 1
  end

  it "abides by onlyif as expected while writing" do
    r = RemainingBytesData.new
    r.first = 0x01
    r.rest = Bytes.new 4
    io2 = IO::Memory.new
    r.write io2
    io2.rewind

    io2.size.should eq 1
  end

  it "writes remaining bytes" do
    io = IO::Memory.new
    io.write_byte 0x02
    rest = Bytes.new 4, &.to_u8
    io.write rest
    io.rewind

    r = RemainingBytesData.new
    r.first = 0x02
    r.rest = rest

    io2 = IO::Memory.new
    r.write io2
    io2.rewind

    io2.to_slice.should eq(io.to_slice)
  end
end
