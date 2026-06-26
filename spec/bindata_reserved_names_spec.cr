require "./helper"

# Audit Tier 0.4 — the `inherited` hook generates a shortcut macro named after
# every BinData subclass. A subclass whose underscored name matches a DSL macro
# (e.g. `Field` -> `field`) used to clobber that macro globally, breaking the
# DSL for every class defined afterwards.
#
# These empty subclasses have names that collide with DSL macros / API methods.
# Defining them must NOT generate clobbering shortcut macros.
class Field < BinData
  endian big
end

class Bits < BinData
  endian big
end

class Endian < BinData
  endian big
end

class Group < BinData
  endian big
end

class Custom < BinData
  endian big
end

# Defined AFTER the colliding types above: this only compiles if `endian`,
# `field`, `bit_field`, `bits`, `bool` and `group` were left intact.
class StillWorks < BinData
  endian big

  field x : UInt8 = 0x11_u8

  bit_field do
    bits 4, hi
    bool flag
    bits 3, lo
  end

  group :grp do
    field z : UInt8 = 0x22_u8
  end
end

# A namespaced type underscores to `reserved_names_field` (not `field`), so it
# must never collide with the DSL regardless of its short name.
module ReservedNames
  class Field < BinData
    endian big
  end
end

class StillWorksNamespaced < BinData
  endian big
  field q : UInt8 = 0x33_u8
end

describe "reserved DSL macro names" do
  it "keeps the DSL intact after colliding type names are defined (Tier 0.4)" do
    data = StillWorks.new
    data.x.should eq(0x11_u8)
    data.grp.z.should eq(0x22_u8)

    data.hi = 0xa_u8
    data.flag = true
    data.lo = 0x5_u8

    io = IO::Memory.new
    io.write_bytes(data)
    io.rewind

    rt = io.read_bytes(StillWorks)
    rt.x.should eq(0x11_u8)
    rt.hi.should eq(0xa_u8)
    rt.flag.should eq(true)
    rt.lo.should eq(0x5_u8)
    rt.grp.z.should eq(0x22_u8)
  end

  it "does not collide for namespaced type names" do
    StillWorksNamespaced.new.q.should eq(0x33_u8)
  end
end
