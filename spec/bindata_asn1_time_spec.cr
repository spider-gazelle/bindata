require "./helper"

# Second-pass audit P2 (batch b) — UTCTime / GeneralizedTime had no accessor,
# yet every X.509 certificate encodes its validity dates as one of them.
#   get_time  -> Time (normalised to UTC), handles both tags
#   set_time  -> canonical DER form (default GeneralizedTime)

private def time_ber(tag : ASN1::BER::UniversalTags, text : String) : ASN1::BER
  ber = ASN1::BER.new
  ber.tag_class = ASN1::BER::TagClass::Universal
  ber.tag_number = tag
  ber.payload = text.to_slice
  ber
end

describe "ASN1::BER#get_time" do
  it "reads a GeneralizedTime in UTC" do
    t = time_ber(ASN1::BER::UniversalTags::GeneralizedTime, "20250708120000Z").get_time
    t.should eq(Time.utc(2025, 7, 8, 12, 0, 0))
  end

  it "reads a UTCTime and applies the RFC 5280 year pivot" do
    # YY < 50 => 20YY
    time_ber(ASN1::BER::UniversalTags::UTCTime, "250708120000Z").get_time
      .should eq(Time.utc(2025, 7, 8, 12, 0, 0))
    # YY >= 50 => 19YY
    time_ber(ASN1::BER::UniversalTags::UTCTime, "500708120000Z").get_time
      .should eq(Time.utc(1950, 7, 8, 12, 0, 0))
  end

  it "reads a UTCTime without seconds" do
    time_ber(ASN1::BER::UniversalTags::UTCTime, "2507081200Z").get_time
      .should eq(Time.utc(2025, 7, 8, 12, 0, 0))
  end

  it "normalises a numeric offset to UTC" do
    # 12:00 at +01:00 is 11:00 UTC
    time_ber(ASN1::BER::UniversalTags::GeneralizedTime, "20250708120000+0100").get_time
      .should eq(Time.utc(2025, 7, 8, 11, 0, 0))
    # 12:00 at -0230 is 14:30 UTC
    time_ber(ASN1::BER::UniversalTags::UTCTime, "250708120000-0230").get_time
      .should eq(Time.utc(2025, 7, 8, 14, 30, 0))
  end

  it "reads a UTCTime with no seconds and a numeric offset" do
    time_ber(ASN1::BER::UniversalTags::UTCTime, "2507081200+0100").get_time
      .should eq(Time.utc(2025, 7, 8, 11, 0, 0))
  end

  it "rejects a time zone offset out of range" do
    expect_raises(ASN1::InvalidPayload) do
      time_ber(ASN1::BER::UniversalTags::GeneralizedTime, "20250708120000+9999").get_time
    end
  end

  it "rejects an out-of-range component" do
    # month 13 matches the regex but Time.utc rejects it
    expect_raises(ASN1::InvalidPayload) do
      time_ber(ASN1::BER::UniversalTags::GeneralizedTime, "20251308120000Z").get_time
    end
  end

  it "reads fractional seconds on a GeneralizedTime" do
    t = time_ber(ASN1::BER::UniversalTags::GeneralizedTime, "20250708120000.5Z").get_time
    t.should eq(Time.utc(2025, 7, 8, 12, 0, 0, nanosecond: 500_000_000))
  end

  it "raises on a missing time zone" do
    expect_raises(ASN1::InvalidPayload) do
      time_ber(ASN1::BER::UniversalTags::GeneralizedTime, "20250708120000").get_time
    end
  end

  it "raises on malformed content" do
    expect_raises(ASN1::InvalidPayload) do
      time_ber(ASN1::BER::UniversalTags::UTCTime, "not-a-time").get_time
    end
  end

  it "raises on a non-time tag" do
    ber = ASN1::BER.new
    ber.set_integer(5)
    expect_raises(ASN1::InvalidTag) { ber.get_time }
  end
end

describe "ASN1::BER#set_time" do
  it "encodes a GeneralizedTime by default" do
    ber = ASN1::BER.new
    ber.set_time(Time.utc(2025, 7, 8, 12, 0, 0))
    ber.tag_number.should eq(ASN1::BER::UniversalTags::GeneralizedTime.to_i)
    String.new(ber.payload).should eq("20250708120000Z")
  end

  it "encodes a UTCTime when asked" do
    ber = ASN1::BER.new
    ber.set_time(Time.utc(2025, 7, 8, 12, 0, 0), ASN1::BER::UniversalTags::UTCTime)
    ber.tag_number.should eq(ASN1::BER::UniversalTags::UTCTime.to_i)
    String.new(ber.payload).should eq("250708120000Z")
  end

  it "converts a non-UTC time to UTC before encoding" do
    ber = ASN1::BER.new
    ber.set_time(Time.local(2025, 7, 8, 13, 0, 0, location: Time::Location.fixed(3600)))
    String.new(ber.payload).should eq("20250708120000Z")
  end

  it "accepts the UTCTime upper boundary year (2049) but rejects 2050" do
    ber = ASN1::BER.new
    ber.set_time(Time.utc(2049, 6, 1, 0, 0, 0), ASN1::BER::UniversalTags::UTCTime)
    String.new(ber.payload).should eq("490601000000Z")
    expect_raises(ASN1::InvalidPayload) do
      ASN1::BER.new.set_time(Time.utc(2050, 1, 1), ASN1::BER::UniversalTags::UTCTime)
    end
  end

  it "rejects a UTCTime below the 1950 boundary" do
    expect_raises(ASN1::InvalidPayload) do
      ASN1::BER.new.set_time(Time.utc(1949, 12, 31), ASN1::BER::UniversalTags::UTCTime)
    end
  end

  it "round-trips through get_time" do
    original = Time.utc(1999, 12, 31, 23, 59, 59)
    ber = ASN1::BER.new
    ber.set_time(original, ASN1::BER::UniversalTags::UTCTime)
    ber.get_time.should eq(original)
  end
end
