require "./bindata/exceptions"
require "./bindata/bitfield"

abstract class BinData
  INDEX          = [-1]
  BIT_PARTS      = [] of Nil
  CUSTOM_TYPES   = [] of BinData.class
  RESERVED_NAMES = ["inherited", "included", "extended", "method_missing",
                    "method_added", "finished"]

  macro inherited
    PARTS = [] of Nil
    ENDIAN = ["system"]
    KLASS_NAME = [{{@type.name.id}}]
    REMAINING = [] of Nil
    BEFORE_SERIALIZE = [] of Nil
    AFTER_DESERIALIZE = [] of Nil
    {% BinData::CUSTOM_TYPES << @type.name.id %}

    {% for custom_type in BinData::CUSTOM_TYPES %}
    {% method_name = custom_type.gsub(/::/, "_").underscore.id %}
      {% unless RESERVED_NAMES.includes? method_name.stringify %}
        macro {{ method_name }}(name, onlyif = nil, verify = nil, value = nil)
          field \{{name.id}} : {{custom_type}} = {{ custom_type }}.new
        end
      {% end %}
    {% end %}

    def self.bit_fields
      {{@type.ancestors[0].id}}.bit_fields.merge(@@bit_fields)
    end

    macro finished
      __build_methods__
    end
  end

  @@bit_fields = {} of String => BitField

  def self.bit_fields
    @@bit_fields
  end

  def __format__ : IO::ByteFormat
    IO::ByteFormat::SystemEndian
  end

  def self.from_slice(bytes : Slice, format : IO::ByteFormat = IO::ByteFormat::SystemEndian)
    io = IO::Memory.new(bytes)
    from_io(io, format)
  end

  def to_slice
    io = IO::Memory.new
    io.write_bytes self
    io.to_slice
  end

  macro endian(format)
    def __format__ : IO::ByteFormat
      {% format = format.id.stringify %}
      {% ENDIAN[0] = format.id.stringify %}
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

  def write(io : IO)
    __perform_write__(io)
    0_i64
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

      part_name = ""

      begin
        {% for part in PARTS %}
          %endian = {% if part[:endian] %}{{ part[:endian] }}{% else %}__format__{% end %}
          {% if part[:type] == "bitfield" %}
            part_name = {{"bitfield." + BIT_PARTS[part[:name]].keys[0].id.stringify}}
          {% else %}
            part_name = {{part[:name].id.stringify}}
          {% end %}

          {% if part[:onlyif] %}
            %onlyif = ({{part[:onlyif]}}).call
            if %onlyif
          {% end %}

          {% if part[:type] == "basic" %}
            {% part_type = part[:cls].resolve %}
            {% if part_type.is_a?(Union) %}
              @{{part[:name]}} = io.read_bytes({{part_type.types.reject(&.nilable?)[0]}}, %endian)
            {% elsif part_type.union? %}
              @{{part[:name]}} = io.read_bytes({{part_type.union_types.reject(&.nilable?)[0]}}, %endian)
            {% else %}
              @{{part[:name]}} = io.read_bytes({{part[:cls]}}, %endian)
            {% end %}

          {% elsif part[:type] == "array" %}
            %size = ({{part[:length]}}).call.not_nil!
            @{{part[:name]}} = [] of {{part[:cls]}}
            (0...%size).each do
              @{{part[:name]}} << io.read_bytes({{part[:cls]}}, %endian)
            end

          {% elsif part[:type] == "variable_array" %}
            @{{part[:name]}} = [] of {{part[:cls]}}
            loop do
              # Stop if the callback indicates there is no more
              break unless ({{part[:read_next]}}).call
              @{{part[:name]}} << io.read_bytes({{part[:cls]}}, %endian)
            end

          {% elsif part[:type] == "enum" %}
            @{{part[:name]}} = {{part[:enum_type]}}.from_value(io.read_bytes({{part[:cls]}}, %endian))

          {% elsif part[:type] == "group" %}
            @{{part[:name]}} = {{part[:cls]}}.new
            @{{part[:name]}}.parent = self
            @{{part[:name]}}.read(io)

          {% elsif part[:type] == "bytes" %}
            # There is a length calculation
            %size = ({{part[:length]}}).call.not_nil!
            %buf = Bytes.new(%size)
            io.read_fully(%buf)
            @{{part[:name]}} = %buf

          {% elsif part[:type] == "string" %}
            {% if part[:length] %}
              # There is a length calculation
              %size = ({{part[:length]}}).call.not_nil!
              %buf = Bytes.new(%size)
              io.read_fully(%buf)
              @{{part[:name]}} = String.new(%buf)
            {% else %}
              # Assume the string is 0 terminated
              @{{part[:name]}} = (io.gets('\0') || "")[0..-2]
            {% end %}

          {% elsif part[:type] == "bitfield" %}
            %bitfield = self.class.bit_fields["{{part[:cls]}}_{{part[:name]}}"]
            %bitfield.read(io, %endian)

            # Apply the values (with their correct type)
            {% for name, value in BIT_PARTS[part[:name]] %}
              %value = %bitfield[{{name.id.stringify}}]
              @{{name}} = %value.as({{value[0]}})
            {% end %}
          {% end %}

          {% if part[:onlyif] %}
            end
          {% end %}

          {% if part[:verify] %}
            if !({{part[:verify]}}).call
              raise ReadingVerificationException.new "{{@type}}", "{{part[:name]}}", "{{part[:type].id}}"
            end
          {% end %}
        {% end %}

        {% if REMAINING.size > 0 %}
          part_name = {{REMAINING[0][:name].id.stringify}}

          {% if REMAINING[0][:onlyif] %}
            %onlyif = ({{REMAINING[0][:onlyif]}}).call
            if %onlyif
          {% end %}
          %buf = Bytes.new io.size - io.pos
          io.read_fully %buf
          @{{REMAINING[0][:name]}} = %buf
          {% if REMAINING[0][:onlyif] %}
            end
          {% end %}
          {% if REMAINING[0][:verify] %}
            if !({{REMAINING[0][:verify]}}).call
              raise ReadingVerificationException.new "{{@type}}", "{{REMAINING[0][:name]}}", "{{REMAINING[0][:type].id}}"
            end
          {% end %}
        {% end %}

      rescue ex : VerificationException | ParseError
        raise ex
      rescue error
        raise ParseError.new "{{@type.id}}", "#{part_name}", error
      end

      begin
        {% for callback in AFTER_DESERIALIZE %}
          begin
            {{ callback.body }}
          end
        {% end %}
      rescue error
        raise RuntimeError.new("error in after deserialize callback", cause: error)
      end

      io
    end

    protected def __perform_write__(io : IO) : IO
      # Support inheritance
      super(io)

      begin
        {% for callback in BEFORE_SERIALIZE %}
          begin
            {{ callback.body }}
          end
        {% end %}
      rescue error
        raise RuntimeError.new("error in before serialize callback", cause: error)
      end

      part_name = ""

      begin
        {% for part in PARTS %}
          %endian = {% if part[:endian] %}{{ part[:endian] }}{% else %}__format__{% end %}

          {% if part[:type] == "bitfield" %}
            part_name = {{"bitfield." + BIT_PARTS[part[:name]].keys[0].id.stringify}}
          {% else %}
            part_name = {{part[:name].id.stringify}}
          {% end %}

          {% if part[:onlyif] %}
            %onlyif = ({{part[:onlyif]}}).call
            if %onlyif
          {% end %}

          {% if part[:value] %}
            # check if we need to configure the value
            %value = ({{part[:value]}}).call
            # This ensures numbers are cooerced to the correct type
            # NOTE:: `if %value.is_a?(Number)` had issues with `String` due to `.new(0)`
            {% if part[:type] == "basic" %}
              @{{part[:name]}} = {{part[:cls]}}.new(0) | %value
            {% else %}
              @{{part[:name]}} = %value || @{{part[:name]}}
            {% end %}
          {% end %}

          {% if part[:type] == "basic" %}
            {% part_type = part[:cls].resolve %}
            {% if part_type.is_a?(Union) || part_type.union? %}
              if __temp_{{part[:name]}} = @{{part[:name]}}
                io.write_bytes(__temp_{{part[:name]}}, %endian)
              else
                raise NilAssertionError.new("unable to write nil value for #{self.class}##{{{part[:name].stringify}}}")
              end
            {% else %}
              io.write_bytes(@{{part[:name]}}, %endian)
            {% end %}

          {% elsif part[:type] == "array" || part[:type] == "variable_array" %}
            @{{part[:name]}}.each do |part|
              io.write_bytes(part, %endian)
            end

          {% elsif part[:type] == "enum" %}
            %value = {{part[:cls]}}.new(@{{part[:name]}}.value)
            io.write_bytes(%value, %endian)

          {% elsif part[:type] == "group" %}
            @{{part[:name]}}.parent = self
            io.write_bytes(@{{part[:name]}}, %endian)

          {% elsif part[:type] == "bytes" %}
            io.write(@{{part[:name]}})

          {% elsif part[:type] == "string" %}
            io.write(@{{part[:name]}}.to_slice)
            {% if !part[:length] %}
              io.write_byte(0_u8)
            {% end %}

          {% elsif part[:type] == "bitfield" %}
            # Apply any values
            %bitfield = self.class.bit_fields["{{part[:cls]}}_{{part[:name]}}"]
            {% for name, value in BIT_PARTS[part[:name]] %}
              {% if value[1] %}
                %value = ({{value[1]}}).call
                @{{name}} = %value || @{{name}}
              {% end %}

              %bitfield[{{name.id.stringify}}] = @{{name}}.not_nil!
            {% end %}

            %bitfield.write(io, %endian)
          {% end %}

          {% if part[:onlyif] %}
            end
          {% end %}

          {% if part[:verify] %}
            if !({{part[:verify]}}).call
              raise WritingVerificationException.new "{{@type}}", "{{part[:name]}}", "{{part[:type].id}}"
            end
          {% end %}
        {% end %}

        {% if REMAINING.size > 0 %}
          part_name = {{REMAINING[0][:name].id.stringify}}

          {% if REMAINING[0][:onlyif] %}
            %onlyif = ({{REMAINING[0][:onlyif]}}).call
            if %onlyif
          {% end %}
          io.write(@{{REMAINING[0][:name]}})
          {% if REMAINING[0][:onlyif] %}
            end
          {% end %}
          {% if REMAINING[0][:verify] %}
            if !({{REMAINING[0][:verify]}}).call
              raise WritingVerificationException.new "{{@type}}", "{{REMAINING[0][:name]}}", "{{REMAINING[0][:type].id}}"
            end
          {% end %}
        {% end %}

      rescue ex : VerificationException | WriteError
        raise ex
      rescue error
        raise WriteError.new "{{@type.id}}", "#{part_name}", error
      end

      io
    end
  end

  macro bits(size, name, value = nil, default = nil)
    {% resolved_type = nil %}

    {% if name.is_a?(TypeDeclaration) %}
      {% if name.value %}
        {% default = name.value %}
      {% end %}
      {% if name.type %}
        {% resolved_type = name.type.resolve %}
      {% end %}
      {% name = name.var %}
    {% elsif name.is_a?(Assign) %}
      {% if name.value %}
        {% default = name.value %}
      {% end %}
      {% name = name.target %}
    {% end %}

    %field = @@bit_fields["{{KLASS_NAME[0]}}_{{INDEX[0]}}"]?
    raise "#{KLASS_NAME[0]}#{ '#' }{{name}} is not defined in a bitfield. Using bitfield macro outside of a bitfield" unless %field
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

    {% if resolved_type && resolved_type < Enum %}
      def {{name.id}} : {{resolved_type}}
        {{resolved_type}}.from_value(@{{name.id}})
      end

      def {{name.id}}=(value : {{resolved_type}})
        # Ensure the correct type is being assigned
        @{{name.id}} = @{{name.id}}.class.new(0) | value.value
      end
    {% end %}
  end

  @[Deprecated("Use `#bits` instead")]
  macro enum_bits(size, name)
    {% if name.is_a?(SymbolLiteral) %}
      {% name = name.stringify[1..-1].id %}
    {% end %}

    bits {{size}}, {{name}}
  end

  macro bool(name, default = false)
    {% if name.is_a?(Assign) %}
      {% if name.value %}
        {% default = name.value %}
      {% end %}
      {% name = name.target %}
    {% end %}

    bits(1, {{name}}, default: ({{default}} ? 1 : 0))

    def {{name.id}} : Bool
      @{{name.id}} == 1
    end

    def {{name.id}}=(value : Bool)
      # Ensure the correct type is being assigned
      @{{name.id}} = UInt8.new(value ? 1 : 0)
    end
  end

  macro bit_field(onlyif = nil, verify = nil, &block)
    {% INDEX[0] = INDEX[0] + 1 %}
    {% BIT_PARTS << {} of Nil => Nil %}
    %bitfield = @@bit_fields["{{KLASS_NAME[0]}}_{{INDEX[0]}}"] = BitField.new

    {{block.body}}

    %bitfield.apply
    {% PARTS << {type: "bitfield", name: INDEX[0], cls: KLASS_NAME[0], onlyif: onlyif, verify: verify} %}
  end

  # }# Encapsulates a bunch of fields by creating a nested BinData class
  macro group(name, onlyif = nil, verify = nil, value = nil, &block)
    class {{name.id.stringify.camelcase.id}} < BinData
      endian({{ENDIAN[0]}})

      # Group fields might need access to data in the parent
      property parent : {{@type.id}}?
      def parent
        @parent.not_nil!
      end

      {{block.body}}
    end

    property {{name.id}} = {{name.id.stringify.camelcase.id}}.new

    {% PARTS << {type: "group", name: name.id, cls: name.id.stringify.camelcase.id, onlyif: onlyif, verify: verify, value: value} %}
  end

  macro remaining_bytes(name, onlyif = nil, verify = nil, default = nil)
    {% REMAINING << {type: "bytes", name: name.id, onlyif: onlyif, verify: verify} %}
    property {{name.id}} : Bytes = {% if default %} {{default}}.to_slice {% else %} Bytes.new(0) {% end %}
  end

  # this needs to be split out so we can resolve the enum base_type
  macro __add_enum_field(name, cls, onlyif, verify, value, encoding, enum_type)
    {% PARTS << {type: "enum", name: name, cls: cls, onlyif: onlyif, verify: verify, value: value, encoding: encoding, enum_type: enum_type} %}
  end

  macro field(type_declaration, onlyif = nil, verify = nil, value = nil, length = nil, read_next = nil, encoding = nil, endian = nil)
    {% if !type_declaration.is_a?(TypeDeclaration) %}
      {% raise "#{type_declaration} must be a TypeDeclaration" %}
    {% end %}

    {% resolved_type = type_declaration.type.resolve %}
    {% default = type_declaration.value %}
    {% name = type_declaration.var %}

    {% if {Int8, UInt8, Int16, UInt16, Int32, UInt32, Int64, UInt64, Int128, UInt128, Float32, Float64}.includes? resolved_type %}
      {% PARTS << {type: "basic", name: name, cls: resolved_type, onlyif: onlyif, verify: verify, value: value, endian: endian} %}
      property {{name.id}} : {{resolved_type}} = {% if default %} {{resolved_type}}.new({{default}}) {% else %} 0 {% end %}
    {% elsif resolved_type == String %}
      {% PARTS << {type: "string", name: name, cls: resolved_type, onlyif: onlyif, verify: verify, length: length, value: value, encoding: encoding} %}
      property {{name.id}} : String = {% if default %} {{default}} {% else %} "" {% end %}
    {% elsif {Bytes, Slice(UInt8)}.includes? resolved_type %}
      {% PARTS << {type: "bytes", name: name, cls: resolved_type, onlyif: onlyif, verify: verify, length: length, value: value} %}
      {% raise "Bytes fields require a length callback" unless length %}
      property {{name.id}} : Bytes = {% if default %} {{default}}.to_slice {% else %} Bytes.new(0) {% end %}
    {% elsif resolved_type < Enum %}
      property {{type_declaration}}
      {% raise "Enum fields require a default value to be provided" unless default %}
      __add_enum_field name: {{name}}, cls: typeof({{default}}.value), onlyif: {{onlyif}}, verify: {{verify}}, value: {{value}}, encoding: {{encoding}}, enum_type: {{resolved_type}}
    {% elsif resolved_type <= Array || resolved_type <= Set %}
      {% if length %}
        {% PARTS << {type: "array", name: name, cls: resolved_type.type_vars[0], onlyif: onlyif, verify: verify, length: length, value: value} %}
      {% elsif read_next %}
        {% PARTS << {type: "variable_array", name: name, cls: resolved_type.type_vars[0], onlyif: onlyif, verify: verify, read_next: read_next, value: value} %}
      {% else %}
        {% raise "Array and Set fields require a length callback or read_next callback" %}
      {% end %}
      property {{name.id}} : {{resolved_type}} = {% if default %} {{default}} {% else %} {{resolved_type}}.new {% end %}
    {% else %}
      {% PARTS << {type: "basic", name: name, cls: resolved_type, onlyif: onlyif, verify: verify, value: value} %}
      property {{type_declaration}}
    {% end %}
  end

  macro before_serialize(&block)
    {% BEFORE_SERIALIZE << block %}
  end

  macro after_deserialize(&block)
    {% AFTER_DESERIALIZE << block %}
  end

  # deprecated:

  @[Deprecated("Use `#field` instead")]
  macro custom(name, onlyif = nil, verify = nil, value = nil)
    {% PARTS << {type: "basic", name: name.var, cls: name.type, onlyif: onlyif, verify: verify, value: value} %}
    property {{name.id}}
  end

  @[Deprecated("Use `#field` instead")]
  macro enum_field(size, name, onlyif = nil, verify = nil, value = nil)
    {% PARTS << {type: "enum", name: name.var, cls: size, onlyif: onlyif, verify: verify, value: value, enum_type: name.type} %}
    property {{name.id}}
  end

  @[Deprecated("Use `#field` instead")]
  macro array(name, length, onlyif = nil, verify = nil, value = nil)
    {% PARTS << {type: "array", name: name.var, cls: name.type, onlyif: onlyif, verify: verify, length: length, value: value} %}
    property {{name.var}} : Array({{name.type}}) = {% if name.value %} {{name.value}} {% else %} [] of {{name.type}} {% end %}
  end

  @[Deprecated("Use `#field` instead")]
  macro variable_array(name, read_next, onlyif = nil, verify = nil, value = nil)
    {% PARTS << {type: "variable_array", name: name.var, cls: name.type, onlyif: onlyif, verify: verify, read_next: read_next, value: value} %}
    property {{name.var}} : Array({{name.type}}) = {% if name.value %} {{name.value}} {% else %} [] of {{name.type}} {% end %}
  end

  {% for vartype in ["UInt8", "Int8", "UInt16", "Int16", "UInt32", "Int32", "UInt64", "Int64", "UInt128", "Int128", "Float32", "Float64"] %}
    {% name = vartype.downcase.id %}

    @[Deprecated("Use `#field` instead")]
    macro {{name}}(name, onlyif = nil, verify = nil, value = nil, default = nil)
      \{% PARTS << {type: "basic", name: name.id, cls: {{vartype.id}}, onlyif: onlyif, verify: verify, value: value} %}
      property \{{name.id}} : {{vartype.id}} = \{% if default %} {{vartype.id}}.new(\{{default}}) \{% else %} 0 \{% end %}
    end

    @[Deprecated("Use `#field` instead")]
    macro {{name}}be(name, onlyif = nil, verify = nil, value = nil, default = nil)
      \{% PARTS << {type: "basic", name: name.id, cls: {{vartype.id}}, onlyif: onlyif, verify: verify, value: value, endian: IO::ByteFormat::BigEndian} %}
      property \{{name.id}} : {{vartype.id}} = \{% if default %} {{vartype.id}}.new(\{{default}}) \{% else %} 0 \{% end %}
    end

    @[Deprecated("Use `#field` instead")]
    macro {{name}}le(name, onlyif = nil, verify = nil, value = nil, default = nil)
      \{% PARTS << {type: "basic", name: name.id, cls: {{vartype.id}}, onlyif: onlyif, verify: verify, value: value, endian: IO::ByteFormat::LittleEndian} %}
      property \{{name.id}} : {{vartype.id}} = \{% if default %} {{vartype.id}}.new(\{{default}}) \{% else %} 0 \{% end %}
    end
  {% end %}

  @[Deprecated("Use `#field` instead")]
  macro string(name, onlyif = nil, verify = nil, length = nil, value = nil, encoding = nil, default = nil)
    {% PARTS << {type: "string", name: name.id, cls: "String".id, onlyif: onlyif, verify: verify, length: length, value: value, encoding: encoding} %}
    property {{name.id}} : String = {% if default %} {{default}}.to_s {% else %} "" {% end %}
  end

  @[Deprecated("Use `#field` instead")]
  macro bytes(name, length, onlyif = nil, verify = nil, value = nil, default = nil)
    {% PARTS << {type: "bytes", name: name.id, cls: "Bytes".id, onlyif: onlyif, verify: verify, length: length, value: value} %}
    property {{name.id}} : Bytes = {% if default %} {{default}}.to_slice {% else %} Bytes.new(0) {% end %}
  end
end
