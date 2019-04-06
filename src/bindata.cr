class BinData
  macro inherited
    PARTS = [] of Nil
    INDEX = [-1]
    BIT_PARTS = [] of Nil

    macro finished
      __build_methods__
    end
  end

  @@bit_fields = [] of BitField

  def __format__ : IO::ByteFormat
    IO::ByteFormat::SystemEndian
  end

  macro endian(format)
    def __format__ : IO::ByteFormat
      {% format = format.id.stringify %}
      {% if format == "little" %}
        IO::ByteFormat::LittleEndian
      {% elsif format == "big" %}
        IO::ByteFormat::BigEndian
      {% elsif format == "network" %}
        IO::ByteFormat::NetworkEndian
      {% else %}
        IO::ByteFormat::SystemEndian
      {% end %}
    end
  end

  def read(io : IO) : IO
    __perform_read__(io)
  end

  protected def __perform_read__(io : IO) : IO
    io
  end

  def write(io : IO) : IO
    __perform_write__(io)
  end

  protected def __perform_write__(io : IO) : IO
    io
  end

  def to_io(io : IO, format : IO::ByteFormat = IO::ByteFormat::SystemEndian)
    write(io)
  end

  def self.from_io(io : IO, format : IO::ByteFormat = IO::ByteFormat::SystemEndian)
    data = self.new
    data.read(io)
    data
  end

  macro __build_methods__
    protected def __perform_read__(io : IO) : IO
      # Support inheritance
      super(io)

      {% for part in PARTS %}
        {% if part[3] %}
          %onlyif = ({{part[3]}}).call
          if %onlyif
        {% end %}

        {% if part[0] == "basic" %}
          @{{part[1]}} = io.read_bytes({{part[2]}}, __format__)

        {% elsif part[0] == "array" %}
          %size = ({{part[4]}}).call.not_nil!
          @{{part[1]}} = [] of {{part[2]}}
          (0...%size).each do
            @{{part[1]}} << io.read_bytes({{part[2]}}, __format__)
          end

        {% elsif part[0] == "enum" %}
          %value = io.read_bytes({{part[2]}}, __format__)
          @{{part[1]}} = {{part[6]}}.from_value(%value)

        {% elsif part[0] == "group" %}
          @{{part[1]}} = {{part[2]}}.new
          @{{part[1]}}.parent = self
          @{{part[1]}}.read(io)

         {% elsif part[0] == "string" %}
          {% if part[4] %}
            # There is a length calculation
            %size = ({{part[4]}}).call.not_nil!
            %buf = Bytes.new(%size)
            io.read_fully(%buf)
            @{{part[1]}} = String.new(%buf)
          {% else %}
            # Assume the string is 0 terminated
            @{{part[1]}} = io.gets('\0')
          {% end %}

        {% elsif part[0] == "bitfield" %}
          %bitfield = @@bit_fields[{{part[1]}}]
          %bitfield.read(io, __format__)

          # Apply the values (with their correct type)
          {% for name, value in BIT_PARTS[part[1]] %}
            %value = %bitfield[{{name.id.stringify}}]
            @{{name}} = %value.as({{value[0]}})
          {% end %}
        {% end %}

        {% if part[3] %}
          end
        {% end %}
      {% end %}

      io
    end

    protected def __perform_write__(io : IO) : IO
      # Support inheritance
      super(io)

      {% for part in PARTS %}
        {% if part[3] %}
          %onlyif = ({{part[3]}}).call
          if %onlyif
        {% end %}

        {% if part[5] %}
          # check if we need to configure the value
          %value = ({{part[5]}}).call
          # This ensures numbers are cooerced to the correct type
          if %value.is_a?(Number)
            @{{part[1]}} = {{part[2]}}.new(0) | %value
          else
            @{{part[1]}} = %value || @{{part[1]}}
          end
        {% end %}

        {% if part[0] == "basic" %}
          io.write_bytes(@{{part[1]}}, __format__)

        {% elsif part[0] == "array" %}
          @{{part[1]}}.each do |part|
            io.write_bytes(part, __format__)
          end

        {% elsif part[0] == "enum" %}
          %value = {{part[2]}}.new(@{{part[1]}}.to_i)
          io.write_bytes(%value, __format__)

        {% elsif part[0] == "group" %}
          @{{part[1]}}.parent = self
          io.write_bytes(@{{part[1]}}, __format__)

         {% elsif part[0] == "string" %}
          io.write(@{{part[1]}}.to_slice)
          {% if !part[4] %}
            io.write_byte('\0')
          {% end %}

        {% elsif part[0] == "bitfield" %}
          # Apply any values
          {% for name, value in BIT_PARTS[part[1]] %}
            {% if value[1] %}
              %value = ({{value[1]}}).call
              @{{name}} = %value || @{{name}}
            {% end %}

            @@bit_fields[{{part[1]}}][{{name.id.stringify}}] = @{{name}}.not_nil!
          {% end %}

          @@bit_fields[{{part[1]}}].write(io, __format__)
        {% end %}

        {% if part[3] %}
          end
        {% end %}
      {% end %}

      io
    end
  end

  # PARTS:
  #  0: parse type
  # 1: var_name
  # 2: class
  # 3: if_proc
  # 4: length
  # 5: value
  # 6: encoding
  {% for vartype in ["UInt8", "Int8", "UInt16", "Int16", "UInt32", "Int32", "UInt64", "Int64", "UInt128", "Int128"] %}
    {% name = vartype.downcase.id %}

    macro {{name}}(name, onlyif = nil, value = nil, default = nil)
      \{% PARTS << {"basic", name.id, {{vartype.id}}, onlyif, nil, value} %}
      property \{{name.id}} : {{vartype.id}} = \{% if default %} {{vartype.id}}.new(\{{default}}) \{% else %} 0 \{% end %}
    end
  {% end %}

  macro string(name, onlyif = nil, length = nil, value = nil, encoding = nil, default = nil)
    {% PARTS << {"string", name.id, "String".id, onlyif, length, value, encoding} %}
    property {{name.id}} : String = {% if default %} {{default}}.to_s {% else %} "" {% end %}
  end

  macro bits(size, name, value = nil, default = nil)
    %field = @@bit_fields[{{INDEX[0]}}]
    %field.bits({{size}}, {{name.id.stringify}})

    {% if size <= 8 %}
      {% BIT_PARTS[INDEX[0]][name.id] = {"UInt8".id, value} %}
      property {{name.id}} : UInt8 = {% if default %} {{default}}.to_u8 {% else %} 0 {% end %}
    {% elsif size <= 16 %}
      {% BIT_PARTS[INDEX[0]][name.id] = {"UInt16".id, value} %}
      property {{name.id}} : UInt16 = {% if default %} {{default}}.to_u16 {% else %} 0 {% end %}
    {% elsif size <= 32 %}
      {% BIT_PARTS[INDEX[0]][name.id] = {"UInt32".id, value} %}
      property {{name.id}} : UInt32 = {% if default %} {{default}}.to_u32 {% else %} 0 {% end %}
    {% elsif size <= 64 %}
      {% BIT_PARTS[INDEX[0]][name.id] = {"UInt64".id, value} %}
      property {{name.id}} : UInt64 = {% if default %} {{default}}.to_u64 {% else %} 0 {% end %}
    {% elsif size <= 128 %}
      {% BIT_PARTS[INDEX[0]][name.id] = {"UInt128".id, value} %}
      property {{name.id}} : UInt128 = {% if default %} {{default}}.to_u128 {% else %} 0 {% end %}
    {% else %}
      {{ "bits greater than 128 are not supported".id }}
    {% end %}
  end

  macro enum_bits(size, name)
    {% if name.value %}
      bits({{size}}, {{name.var}}, default: {{name.value}}.to_i)
    {% else %}
      bits({{size}}, {{name.var}})
    {% end %}

    def {{name.var}} : {{name.type}}
      {{name.type}}.from_value(@{{name.var}})
    end

    def {{name.var}}=(value : {{name.type}})
      # Ensure the correct type is being assigned
      @{{name.var}} = @{{name.var}}.class.new(0) | value.to_i
    end
  end

  macro bool(name, default = false)
    bits(1, {{name.id}}, default: ({{default}} ? 1 : 0) )

    def {{name.id}} : Bool
      @{{name.id}} == 1
    end

    def {{name.id}}=(value : Bool)
      # Ensure the correct type is being assigned
      @{{name.id}} = UInt8.new(value ? 1 : 0)
    end
  end

  macro bit_field(onlyif = nil, &block)
    @@bit_fields << BitField.new
    {% INDEX[0] = INDEX[0] + 1 %}
    {% BIT_PARTS << {} of Nil => Nil %}

    {{block.body}}

    @@bit_fields[{{INDEX[0]}}].apply
    {% PARTS << {"bitfield", INDEX[0], nil, onlyif, nil, nil} %}
  end

  macro custom(name, onlyif = nil, value = nil)
    {% PARTS << {"basic", name.var, name.type, onlyif, nil, value, nil} %}
    property {{name.id}}
  end

  macro enum_field(size, name, onlyif = nil, value = nil)
    {% PARTS << {"enum", name.var, size, onlyif, nil, value, name.type} %}
    property {{name.id}}
  end

  macro array(name, length, onlyif = nil, value = nil)
    {% PARTS << {"array", name.var, name.type, onlyif, length, value, nil} %}
    property {{name.var}} : Array({{name.type}}) = {% if name.value %} {{name.value}} {% else %} [] of {{name.type}} {% end %}
  end

  # }# Encapsulates a bunch of fields by creating a nested BinData class
  macro group(name, onlyif = nil, value = nil, &block)
    class {{name.id.stringify.camelcase.id}} < BinData
      # Group fields might need access to data in the parent
      property parent : {{@type.id}}?
      def parent
        @parent.not_nil!
      end

      {{block.body}}
    end

    property {{name.id}} = {{name.id.stringify.camelcase.id}}.new

    {% PARTS << {"group", name.id, name.id.stringify.camelcase.id, onlyif, nil, value, nil} %}
  end
end

require "./bindata/bitfield"
