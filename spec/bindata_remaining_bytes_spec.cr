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

    expect_raises BinData::VerificationException, "Failed to verify reading bytes at RemainingBytesData.rest" do
      io.read_bytes RemainingBytesData
    end
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
end
