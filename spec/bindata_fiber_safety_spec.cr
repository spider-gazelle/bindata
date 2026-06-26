require "./helper"

# Audit Tier 2.1 — the per-class `BitField` was a singleton mutated in place
# during read/write (`@buffer`, `@values`). Two fibers (de)serializing instances
# of the same class concurrently raced on that shared state, corrupting values
# (and, under -Dpreview_mt, mutating a shared Hash from multiple threads).
#
# These stress tests only exercise the race under -Dpreview_mt (true parallelism);
# in single-threaded mode the bitfield ops never yield, so they pass trivially.
# The CI runs the suite under -Dpreview_mt so this stays a real regression guard.

# Sub-byte and multi-byte fields exercise the buffer-`shift` path (historically
# the most race-prone code), not just a byte-aligned read.
class BitRace < BinData
  endian big

  bit_field do
    bits 3, :a
    bits 5, :b
    bits 16, :c
    bits 8, :d
  end
end

private def stress(fiber_count : Int32, iterations : Int32, &block : Int32 -> Bool)
  done = Channel(Int32).new
  fiber_count.times do |f|
    spawn do
      mismatches = 0
      iterations.times do
        mismatches += 1 unless block.call(f)
        Fiber.yield
      end
      done.send(mismatches)
    end
  end
  total = 0
  fiber_count.times { total += done.receive }
  total
end

describe "BinData bitfield fiber-safety" do
  it "round-trips a bitfield struct concurrently without corruption (Tier 2.1)" do
    mismatches = stress(8, 5_000) do |f|
      a = (f & 0x7).to_u8
      b = ((f &* 5) & 0x1f).to_u8
      c = ((f &* 9973) & 0xffff).to_u16
      d = (f &* 71).to_u8!

      obj = BitRace.new
      obj.a = a
      obj.b = b
      obj.c = c
      obj.d = d

      io = IO::Memory.new
      obj.write(io)
      io.rewind
      rt = io.read_bytes(BitRace)

      rt.a == a && rt.b == b && rt.c == c && rt.d == d
    end
    mismatches.should eq(0)
  end

  it "round-trips ASN.1 BER concurrently (Identifier/Length bitfields)" do
    mismatches = stress(8, 3_000) do |f|
      tag = f % 30 # < 31, so no extended-identifier path
      payload = Bytes[f.to_u8!, (f &* 2).to_u8!, (f &* 3).to_u8!]

      ber = ASN1::BER.new
      ber.tag_number = tag
      ber.payload = payload

      io = IO::Memory.new
      ber.write(io)
      io.rewind
      rt = io.read_bytes(ASN1::BER)

      rt.tag_number == tag && rt.payload == payload
    end
    mismatches.should eq(0)
  end
end
