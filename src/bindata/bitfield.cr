class BinData::BitField
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
    # Extra byte used when writing to IO
    @buffer = Bytes.new(@bitsize // 8)
  end

  def shift(buffer, num_bits, start_byte = 0)
    bytes = buffer.size
    remaining_bytes = bytes - start_byte
    return buffer if remaining_bytes <= 0

    # Shift the one byte
    if remaining_bytes == 1
      buffer[start_byte] = buffer[start_byte] << num_bits
      return buffer
    end

    # Shift the two bytes
    io = IO::Memory.new(buffer)
    io.pos = start_byte
    value = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
    value = value << num_bits

    io.pos = start_byte
    io.write_bytes(value, IO::ByteFormat::BigEndian)

    return buffer if remaining_bytes == 2

    # Adjust all the remaining bytes
    index = start_byte + 2
    loop do
      previous = index - 1

      # Shift the next bit (as a 16bit var so we get the overflow)
      value = (0_u16 | buffer[index]) << num_bits
      # Save the adjustment
      buffer[index] = 0_u8 | value
      # Save the shifted value
      buffer[previous] = buffer[previous] | (value >> 8)

      # Move forward by 1 byte
      index += 1
      break if index >= bytes
    end
    buffer
  end

  def read(input, format) # ameba:disable Metrics/CyclomaticComplexity
    # Fill the buffer
    buffer = @buffer.not_nil!
    input.read_fully(buffer)

    # TODO:: Check if we need to re-order the bytes
    # if format == IO::ByteFormat::LittleEndian
    # end

    @mappings.each do |name, size|
      # Read out the data we are after using this buffer
      io = IO::Memory.new(buffer)
      io.rewind

      if size <= 8
        value = io.read_bytes(UInt8, IO::ByteFormat::BigEndian)

        if size < 8
          # Shift the bits we're interested in towards 0 (as they are high bits)
          value = value >> (8 - size)
          # Mask the bits we are interested in
          value = value & ((1_u8 << size) - 1_u8)
        end
      elsif size <= 16
        value = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)

        if size < 16
          # Shift the bits we're interested in towards 0 (as they are high bits)
          value = value >> (16 - size)
          # Mask the bits we are interested in
          value = value & ((1_u16 << size) - 1_u16)
        end
      elsif size <= 32
        # adjust buffer as required to read the value
        if (io.size - io.pos) < 4
          io_new = IO::Memory.new(Bytes.new(4))
          io_new.write io.to_slice[io.pos..-1]
          io = io_new
          io.rewind
        end

        value = io.read_bytes(UInt32, IO::ByteFormat::BigEndian)
        if size < 32
          # Shift the bits we're interested in towards 0 (as they are high bits)
          value = value >> (32 - size)
          # Mask the bits we are interested in
          value = value & ((1_u32 << size) - 1_u32)
        end
      elsif size <= 64
        # adjust buffer as required to read the value
        if (io.size - io.pos) < 8
          io_new = IO::Memory.new(Bytes.new(8))
          io_new.write io.to_slice[io.pos..-1]
          io = io_new
          io.rewind
        end

        value = io.read_bytes(UInt64, IO::ByteFormat::BigEndian)
        if size < 64
          # Shift the bits we're interested in towards 0 (as they are high bits)
          value = value >> (64 - size)
          # Mask the bits we are interested in
          value = value & ((1_u64 << size) - 1_u64)
        end
      elsif size <= 128
        # adjust buffer as required to read the value
        if (io.size - io.pos) < 16
          io_new = IO::Memory.new(Bytes.new(16))
          io_new.write io.to_slice[io.pos..-1]
          io = io_new
          io.rewind
        end

        value = io.read_bytes(UInt128, IO::ByteFormat::BigEndian)
        if size < 128
          # Shift the bits we're interested in towards 0 (as they are high bits)
          value = value >> (128 - size)
          # Mask the bits we are interested in
          value = value & ((1_u128 << size) - 1_u128)
        end
      else
        raise "no support for structures larger than 128 bits"
      end

      # relies on integer division rounding down
      reduce_buffer = size // 8
      buffer = buffer[reduce_buffer, buffer.size - reduce_buffer]

      # Adjust the buffer
      shift_by = size % 8
      shift(buffer, shift_by) if shift_by > 0

      @values[name] = value
    end

    input
  end

  # ameba:disable Metrics/CyclomaticComplexity
  def write(io, format)
    # Fill the buffer
    bytes = (@bitsize // 8) + 1
    buffer = Bytes.new(bytes)
    output = IO::Memory.new(buffer)
    bitpos = 0
    @mappings.each do |name, size|
      offset = bitpos % 8
      start_byte = bitpos // 8

      num_bytes = size // 8
      num_bytes += 1 if (size % 8) > 0

      # The extra byte lets us easily write to the buffer
      # without overwriting existing bytes
      start_byte += 1 if offset != 0
      value = @values[name]

      # Make sure there is enough space to write the bits
      temp_size = case value
                  when UInt8
                    1
                  when UInt16
                    2
                  when UInt32
                    4
                  when UInt64
                    8
                  when UInt128
                    16
                  else
                    0
                  end
      temp_io = IO::Memory.new(Bytes.new(temp_size))
      temp_io.write_bytes(value, IO::ByteFormat::BigEndian)

      output.pos = start_byte
      output.write(temp_io.to_slice[(temp_size - num_bytes)..-1])
      bitpos += size

      # Calculate how many full bytes to move back
      extra_bytes = (((output.pos - start_byte) * 8) - size) // 8
      if extra_bytes > 0
        first_byte = start_byte + extra_bytes
        (first_byte...bytes).each do |index|
          buffer[index - extra_bytes] = buffer[index]
        end
      end

      # Align the first bit with the start of the byte
      shift_size = 8 - (size % 8)
      shift(buffer, shift_size, start_byte) unless shift_size == 8

      # We need to shift the bytes into the previous byte
      if offset != 0
        num_bits = 8 - offset
        index = start_byte

        loop do
          previous = index - 1

          # Shift the next bit (as a 16bit var so we catch the overflow)
          value = (0_u16 | buffer[index]) << num_bits
          # Save the adjustment
          buffer[index] = 0_u8 | value
          # Save the shifted value
          buffer[previous] = buffer[previous] | (value >> 8)

          # Move forward by 1 byte
          index += 1
          break if index >= bytes
        end
      end
    end

    io.write(buffer[0, bytes - 1])

    0_i64
  end

  def []=(name, value)
    @values[name.to_s] = value
  end

  def [](name)
    @values[name.to_s]
  end
end
