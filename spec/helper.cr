require "spec"
require "../src/bindata"

class Header < BinData
  endian little

  int32 :size, value: ->{ name.bytesize }
  string :name, length: ->{ size }
end

class Body < BinData
  endian big

  uint8 :start, value: ->{ 0_u8 }

  bit_field do
    bits 6, :six, value: ->{ 0b1110_11_u8 }
    bits 3, :three, value: ->{ 0b011_u8 }
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
  custom header : Header = Header.new

  group :body, onlyif: ->{ header.size > 0 } do
    uint8 :start, value: ->{ 1_u8 }, onlyif: ->{ parent.start == 0 }
    uint8 :end, value: ->{ 3_u8 }
  end

  uint8 :end, value: ->{ 0_u8 }
end
