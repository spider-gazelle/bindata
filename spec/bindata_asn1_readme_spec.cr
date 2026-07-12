require "./helper"

# Guards the runnable ASN.1 examples in README.md against silent rot: the README
# code blocks are not compiled by CI (they are illustrative snippets that assume
# an ambient `io`, so a literal compile harness would force rewriting the docs),
# so mirror their behaviour here. If an accessor named in the README is renamed
# or changes contract, one of these fails — a prompt to update the docs.
#
# Each example maps to a "## ASN.1 Helpers" block in README.md; keep them in sync.
describe "README ASN.1 examples" do
  it "builds, writes and reads back a BER integer (README: ASN.1 Helpers)" do
    io = IO::Memory.new

    # Build an element with one of the typed setters and write it to an IO
    ber = ASN1::BER.new
    ber.set_integer(42)
    io.write_bytes(ber)

    # Read it back, then decode with the matching getter
    io.rewind
    ber = io.read_bytes(ASN1::BER)
    ber.tag_class.should eq(ASN1::BER::TagClass::Universal)
    ber.get_integer.should eq(42)
  end

  it "round-trips the typed payload accessors (README: typed accessors table)" do
    ber = ASN1::BER.new

    ber.set_integer(42)
    ber.get_integer.should eq(42)

    ber.set_string("hi")
    ber.get_string.should eq("hi")

    ber.set_boolean(true)
    ber.get_boolean.should eq(true)

    ber.set_object_id("1.2.840.113549.1.1.1")
    ber.get_object_id.to_s.should eq("1.2.840.113549.1.1.1")

    ber.set_hexstring("00ff")
    ber.get_hexstring.should eq("00ff")
  end

  it "splits and rebuilds a constructed element via #children (README: constructed)" do
    child1 = ASN1::BER.new
    child1.set_integer(1)
    child2 = ASN1::BER.new
    child2.set_integer(2)

    # NOTE: the README names this `out`; `out` is a reserved word in Crystal, so
    # this mirror uses `sequence` (the README snippet would not compile verbatim).
    sequence = ASN1::BER.new
    sequence.tag_number = ASN1::BER::UniversalTags::Sequence
    sequence.children = [child1, child2]

    seq = IO::Memory.new(sequence.to_slice).read_bytes(ASN1::BER)
    seq.children.map(&.get_integer).should eq([1, 2])
  end

  it "enforces max_content_length while reading (README: untrusted input)" do
    # A definite element declaring far more content than the cap allows.
    io = IO::Memory.new(Bytes[0x04, 0x7F])

    ber = ASN1::BER.new
    ber.max_content_length = 64
    expect_raises(ASN1::ContentTooLarge) { ber.read(io) }
  end
end
