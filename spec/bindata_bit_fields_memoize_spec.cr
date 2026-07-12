require "./helper"

# `self.bit_fields` is called once per bit_field per (de)serialization; it used to
# rebuild a merged Hash (parent's bit_fields + this class's) on every call. It is
# now memoized per class — bit fields are registered at class-definition time and
# never change at runtime, so the merged map is stable and safe to cache.
describe "BinData.bit_fields memoization" do
  it "still returns the class's registered bit fields" do
    # Body declares two bit_field blocks (see spec/helper.cr).
    Body.bit_fields.size.should eq(2)
  end

  it "returns the same Hash instance across calls (memoized)" do
    Body.bit_fields.should be(Body.bit_fields)
  end

  it "keeps each class's map independent" do
    Body.bit_fields.should_not be(ByteSized.bit_fields)
  end
end
