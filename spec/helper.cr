require "spec"
require "../src/bindata"
require "../src/bindata/asn1"

class Header < BinData
  endian little

  int32 :size, value: ->{ name.bytesize }
  string :name, length: ->{ size }
end

class Body < BinData
  endian big

  uint8 :start, value: ->{ 0_u8 }

  bit_field onlyif: ->{ start == 0 } do
    bits 6, :six, value: ->{ 0b1110_11_u8 }
    bits 3, :three, default: 0b011
    bits 4, :four, value: ->{ 0b1001_u8 }
    bits 11, :teen, value: ->{ 0b1101_1111_101_u16 }
  end

  uint8 :mid, value: ->{ 0_u8 }

  bit_field do
    bits 52, :five, value: ->{ 0xF0_E0_D0_C0_B0_A0_9_u64 }
    bits 12, :eight, value: ->{ 0x104_u16 }
  end

  uint8 :end, value: ->{ 0_u8 }
end

class Wow < BinData
  endian big

  uint8 :start, value: ->{ 0_u8 }
  header :head

  group :body, onlyif: ->{ head.size > 0 } do
    uint8 :start, value: ->{ 1_u8 }, onlyif: ->{ parent.start == 0 }
    uint8 :end, value: ->{ 3_u8 }
  end

  uint8 :end, value: ->{ 0_u8 }
end

class EnumData < BinData
  endian big

  enum Inputs
    VGA
    HDMI
    HDMI2
  end

  uint8 :start, value: ->{ 0_u8 }
  enum_field UInt16, inputs : Inputs = Inputs::HDMI
  bit_field do
    bits 5, :reserved
    bool enabled, default: false
    enum_bits 2, input : Inputs = Inputs::HDMI2
  end
  uint8 :end, value: ->{ 0_u8 }
end

class Inherited < EnumData
  endian big

  bit_field do
    bits 4, :other_high
    bits 4, :other_low
  end
end

class Aligned < BinData
  endian big

  bit_field do
    bits 8, :other, default: 1_u8
  end
end

class ByteSized < BinData
  endian big

  bit_field do
    bits 1, :header
    bits 8, :other, default: 1_u8
    bits 7, :footer
  end
end

class ArrayData < BinData
  endian big

  uint8 :flen, default: 1, value: ->{ first.size }
  array first : Int16 = [15_i16], length: ->{ flen }
  uint8 :slen, value: ->{ 0_u8 | second.size }
  array second : Int8, length: ->{ slen }
end

class VariableArrayData < BinData
  endian big

  uint8 :total_size
  variable_array test : UInt8, read_next: ->{
    # Will continue reading data into the array until
    #  the array size + 2 buffer bytes equals the total size
    (test.size + 2) < total_size
  }
  uint8 :afterdata, default: 1
end

class VerifyData < BinData
  endian big

  uint8 :size
  bytes :bytes, length: ->{ size }
  uint8 :checksum, verify: ->{ checksum == bytes.reduce(0) { |acc, i| acc + i } }
end

class RemainingBytesData < BinData
  endian big

  uint8 :first
  remaining_bytes :rest, onlyif: ->{ first == 0x02 }, verify: ->{ rest.size % 2 == 0 }
end

class ObjectIdentifier < BinData
  endian :big

  bit_field do
    bits 10, :object_type
    bits 22, :instance_number
  end
end

class MixedEndianLittle < BinData
  endian :little

  int16be :big
  int32le :little

  int128 :default
end
