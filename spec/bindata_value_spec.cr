require "./helper"

# Audit Tier 0.3 — a `value:` proc on a Float field used to fail to compile
# (`undefined method '|' for Float64`), because the write-path coercion assumed
# an integer type. Floats are now built directly, integers keep width coercion,
# and any other basic type is assigned as-is.

# A minimal IO-serializable custom type, to exercise the non-numeric "basic"
# branch (assigned as-is, not coerced through `.new(0) | value`).
struct Celsius
  getter value : Int8

  def initialize(@value : Int8 = 0_i8)
  end

  def self.from_io(io : IO, format : IO::ByteFormat) : Celsius
    Celsius.new(io.read_bytes(Int8, format))
  end

  def to_io(io : IO, format : IO::ByteFormat) : Nil
    io.write_bytes(@value, format)
  end
end

class FloatValueData < BinData
  endian big

  field f64 : Float64, value: -> { 1.5 }
  field f32 : Float32, value: -> { 2.25_f32 }
  field from_int64 : Float64, value: -> { 3 }                          # Int proc, coerced to Float64
  field from_int32 : Float32, value: -> { 3 }                          # Int proc, coerced to Float32
  field negative : Float64, value: -> { -7.5 }                         # negative float
  field counter : UInt16, value: -> { 7_u16 }                          # integer path must keep working
  field temp : Celsius = Celsius.new, value: -> { Celsius.new(20_i8) } # custom "else" branch
  field little : Float64, value: -> { 6.5 }, endian: IO::ByteFormat::LittleEndian
end

describe "value: proc coercion" do
  it "supports Float fields with a value proc (Tier 0.3)" do
    io = IO::Memory.new
    io.write_bytes(FloatValueData.new)
    io.rewind

    rt = io.read_bytes(FloatValueData)
    rt.f64.should eq(1.5)
    rt.f32.should eq(2.25_f32)
    rt.from_int64.should eq(3.0)
    rt.from_int32.should eq(3.0_f32)
    rt.negative.should eq(-7.5)
    rt.counter.should eq(7_u16)
    rt.temp.value.should eq(20_i8)
    rt.little.should eq(6.5)
  end
end
