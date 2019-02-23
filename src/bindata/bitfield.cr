
class BinData::BitField
  # Used to extract correct value once read from the buffer
  ENDIAN_BUFFER = Bytes.new(16)
  ENDIAN_IO = IO::Memory.new(ENDIAN_BUFFER)

  def initialize
    @bitsize = 0
    @mappings = {} of String => Int32
    @values = {} of String => UInt8 | UInt16 | UInt32 | UInt64 | UInt128
    # 4 + 12  ==  2bytes
  end

  @buffer : Bytes?

  def bits(size, name)
    raise "no support for structures larger than 128 bits" if size > 128
    @bitsize += size
    @mappings[name.to_s] = size
  end

  def apply
    raise "bit mappings must be divisible by 8" if @bitsize % 8 > 0
    @buffer = Bytes.new(@bitsize / 8)
  end

  def shift(buffer, num_bits)
    io = IO::Memory.new(buffer)
    index = 0
    bytes = buffer.size
    loop do
      # Is there 16 bits remaining?
      if (index + 1) >= bytes
        value = io.read_byte.not_nil!
        io.pos = io.pos - 1

        value = value << num_bits
        io.write_bytes(value)
      else
        value = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
        io.pos = io.pos - 2

        value = value << num_bits
        io.write_bytes(value, IO::ByteFormat::BigEndian)
      end

      # Move forward by 1 byte
      index += 1
      break if index >= bytes

      # UInt16 write should have moved it forward by 2 bytes
      io.pos = io.pos - 1
    end
    buffer
  end

  macro format_value(value, klass, format)
    if {{format}} != IO::ByteFormat::BigEndian
      ENDIAN_IO.rewind
      ENDIAN_IO.write_bytes({{value}}, IO::ByteFormat::BigEndian)
      ENDIAN_IO.rewind
      {{value}} = ENDIAN_IO.read_bytes({{klass}}, {{format}})
    end
  end

  def read(input, format)
    # Fill the buffer
    buffer = @buffer.not_nil!
    input.read(buffer)

    @mappings.each do |name, size|
      # Read out the data we are after using this buffer
      io = IO::Memory.new(buffer)
      io.rewind

      if size <= 8
        value = io.read_bytes(UInt8, IO::ByteFormat::BigEndian)

        if size == 8
          buffer = buffer[1, buffer.size - 1]
        else
          # Shift the bits we're interested in towards 0 (as they are high bits)
          value = value >> (8 - size)
          # Mask the bits we are interested in
          value = value & ((1_u8 << size) - 1_u8)
          shift(buffer, size)
        end
      elsif size <= 16
        value = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)

        if size == 16
          # A nice clean 2 bytes
          buffer = buffer[2, buffer.size - 2]
        else
          # Shift the bits we're interested in towards 0 (as they are high bits)
          value = value >> (16 - size)
          # Mask the bits we are interested in
          value = value & ((1_u16 << size) - 1_u16)
          # Adjust the buffer
          shift_by = 8 - (16 - size)
          buffer = buffer[1, buffer.size - 1]
          shift(buffer, shift_by)
        end

        format_value(value, UInt16, format)
      elsif size <= 32
        value = io.read_bytes(UInt32, IO::ByteFormat::BigEndian)

        if size == 32
          buffer = buffer[4, buffer.size - 4]
        else
          # Shift the bits we're interested in towards 0 (as they are high bits)
          value = value >> (32 - size)
          # Mask the bits we are interested in
          value = value & ((1_u32 << size) - 1_u32)

          # Adjust the buffer
          if size == 24
            buffer = buffer[3, buffer.size - 3]
          else
            shift_by = if size < 24
                          buffer = buffer[2, buffer.size - 2]
                          8 - (24 - size)
                        else
                          buffer = buffer[3, buffer.size - 3]
                          8 - (32 - size)
                        end

            shift(buffer, shift_by)
          end
        end

        format_value(value, UInt32, format)
      elsif size <= 64
        value = io.read_bytes(UInt64, IO::ByteFormat::BigEndian)
        # TODO::
      elsif size <= 128
        # TODO::
        value = io.read_bytes(UInt128, IO::ByteFormat::BigEndian)
      else
        raise "no support for structures larger than 128 bits"
      end

      @values[name] = value
    end

    input
  end

  def write(io, format)
    io
  end

  def []=(name, value)
    @values[name.to_s] = value
  end

  def [](name)
    @values[name.to_s]
  end
end
