require "./helper"

class CallbackTest < BinData
  endian little

  field integer : UInt8

  property external_representation : UInt16 = 0

  before_serialize { self.integer = (external_representation // 2).to_u8 }
  after_deserialize { self.external_representation = integer.to_u16 * 2_u16 }
end

describe "callbacks" do
  it "should run before serialize callbacks" do
    cb = CallbackTest.new
    cb.external_representation = 10

    cb.to_slice[0].should eq 5_u8
  end

  it "should run after deserialize callbacks" do
    io = IO::Memory.new(Bytes[200_u8])
    obj = io.read_bytes(CallbackTest)

    obj.external_representation.should eq 400_u16
  end
end
