# BinData - Parsing Binary Data in Crystal Lang

BinData provides a declarative way to read and write structured binary data.

This means the programmer specifies what the format of the binary data is, and BinData works out how to read and write data in this format. It is an easier (and more readable) alternative.

[![Build Status](https://travis-ci.org/spider-gazelle/bindata.svg?branch=master)](https://travis-ci.org/spider-gazelle/bindata)


## Usage

Firstly, it's recommended that you specify the datas endian.

```crystal
class Header < BinData
  endian big
end
```

Then you can specify the structures fields. There are a few different field types:

1. Core types
   * `uint8`, `int128` which would accept `UInt8` and `Int128` values respectively
2. Custom types
   * anything that is [io serialisable](https://crystal-lang.org/api/0.27.2/IO.html#write_bytes%28object%2Cformat%3AIO%3A%3AByteFormat%3DIO%3A%3AByteFormat%3A%3ASystemEndian%29-instance-method)
3. Bit Fields
   * These are a group of fields who values are defined by the number of bits used to represent their value
   * The total number of bits in a bit field must be divisible by 8
4. Groups
   * These are embedded BinData class with access to the parent fields
   * Useful when a group of fields are related or optional
5. Enums and Bool


### Examples

```crystal
  enum Inputs
    VGA
    HDMI
    HDMI2
  end

  class Packet < BinData
    endian big

    # Default sets the value at initialisation.
    uint8 :start, default: 0xFF_u8

    # Value procs assign these values before writing to an IO, overwriting any
    # existing value
    uint16 :size, value: ->{ text.bytesize + 1 }

    # String fields without a length use `\0` null byte termination
    # Length is being calculated by the size field above
    string :text, length: ->{ size - 1 }

    # Bit fields should only be used when one or more fields are not byte aligned
    # The sum of the bits in a bit field must be divisible by 8
    bit_field do
      # a bits value can be between 1 and 128 bits long
      bits 5, :reserved

      # Bool values are a single bit
      bool :set_input, default: false

      # This enum is represented by 2 bits
      enum_bits 2, input : Inputs = Inputs::HDMI2
    end

    # isolated namespace
    group :extended, onlyif: ->{ start == 0xFF } do
      uint8 :start, default: 0xFF_u8

      # Supports custom objects as long as they implement `from_io`
      custom header : ExtHeader = ExtHeader.new
    end
  end
```

The object above can then be accessed like any other object

```crystal
  pack = io.read_bytes(Packet)
  pack.size # => 12
  pack.text # => "hello world"
  pack.input # => Inputs::HDMI
  pack.set_input # => true
  pack.extended.start # => 255
```


## ASN.1 Helpers

Included in this library are helpers for decoding and writing ASN.1 data, such as those used in SNMP and LDAP

```crystal
require "bindata/asn1"

# Build an object
ber = ASN1::BER.new
ber.tag_number = ASN1::BER::UniversalTags::Integer
ber.payload = Bytes[1]

# Write it to an IO:
io.write_bytes(ber)

# Read data out of an IO:
ber = io.read_bytes(ASN1::BER)
ber.tag_class # => ASN1::BER::TagClass::Universal

```
