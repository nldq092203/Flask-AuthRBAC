from marshmallow import Schema, fields, validate

class PlainRoleSchema(Schema):
    name =fields.Str(dump_only=True)
class RoleSchema(PlainRoleSchema):
    id = fields.Int(dump_only=True)
    default = fields.Bool(dump_only=True)

class UserSchema(Schema):
    id = fields.Int(dump_only=True)
    username = fields.Str(required=True)
    password = fields.Str(required=True, load_only=True)
    roles = fields.List(fields.Nested(PlainRoleSchema()), dump_only=True)
    is_active = fields.Bool(dump_only=True)

class UserUpdateSchema(Schema):
    password = fields.Str(load_only=True)
    roles = fields.List(fields.Int(), load_only=True, validate=validate.Length(min=1))
    is_active = fields.Bool()