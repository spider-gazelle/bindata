require "spec"
require "../src/bindata"
require "../src/bindata/asn1"

class Header < BinData
  endian little

  field size : Int32, value: ->{ name.bytesize }
  field name : String, length: ->{ size }
end

class Body < BinData
  endian big

  field start : UInt8, value: ->{ 0_u8 }

  bit_field onlyif: ->{ start == 0 } do
    bits 6, :six, value: ->{ 0b1110_11_u8 }
    # bits 3, :three, default: 0b011
    bits 3, three = 0b011
    bits 4, four, value: ->{ 0b1001_u8 }
    bits 11, :teen, value: ->{ 0b1101_1111_101_u16 }
  end

  field mid : UInt8, value: ->{ 0_u8 }

  bit_field do
    bits 52, :five, value: ->{ 0xF0_E0_D0_C0_B0_A0_9_u64 }
    bits 12, :eight, value: ->{ 0x104_u16 }
  end

  field end : UInt8, value: ->{ 0_u8 }
end

class Wow < BinData
  endian big

  field start : UInt8, value: ->{ 0_u8 }

  # this is a shortcut for the `Header < BinData` class
  header :head

  group :body, onlyif: ->{ head.size > 0 } do
    field start : UInt8, value: ->{ 1_u8 }, onlyif: ->{ parent.start == 0 }
    field end : UInt8, value: ->{ 3_u8 }
  end

  field end : UInt8, value: ->{ 0_u8 }
end

class EnumData < BinData
  endian big

  enum Inputs : UInt16
    VGA
    HDMI
    HDMI2
  end

  field start : UInt8, value: ->{ 0_u8 }
  field inputs : Inputs = Inputs::HDMI

  bit_field do
    bits 5, :reserved
    bool enabled = false
    bits 2, input : Inputs = Inputs::HDMI2
  end

  field end : UInt8, value: ->{ 0_u8 }
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

  field flen : UInt8 = 1, value: ->{ first.size }
  field first : Array(Int16) = [15_i16], length: ->{ flen }
  field slen : UInt8, value: ->{ 0_u8 | second.size }
  field second : Array(Int8), length: ->{ slen }
end

class VariableArrayData < BinData
  endian big

  field total_size : UInt8
  field test : Array(Int8), read_next: ->{
    # Will continue reading data into the array until
    #  the array size + 2 buffer bytes equals the total size
    (test.size + 2) < total_size
  }
  field afterdata : UInt8 = 1
end

class VerifyData < BinData
  endian big

  field size : UInt8
  field bytes : Bytes, length: ->{ size }
  field checksum : UInt8, verify: ->{ checksum == bytes.reduce(0) { |acc, i| acc + i } }
end

class RemainingBytesData < BinData
  endian big

  field first : UInt8
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

  field big : Int16, endian: IO::ByteFormat::BigEndian
  field little : Int32, endian: IO::ByteFormat::LittleEndian
  field default : Int128
end
