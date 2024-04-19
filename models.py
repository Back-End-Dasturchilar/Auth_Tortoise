from tortoise import fields, models


class User(models.Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(max_length=250, unique=True)
    password = fields.CharField(max_length=250)
    created_at = fields.DatetimeField(auto_now_add=True)

    def __str__(self):
        return self.username


class Category(models.Model):
    id = fields.IntField(pk=True)
    name = fields.CharField(max_length=250)
    created_at = fields.DatetimeField(auto_now_add=True)

    blogs = fields.ReverseRelation['Blog']

    def __str__(self):
        return self.name


class Blog(models.Model):
    id = fields.IntField(pk=True)
    category: fields.ForeignKeyRelation[Category] = fields.ForeignKeyField('models.Category', related_name='blogs')
    title = fields.CharField(max_length=250)
    content = fields.TextField()
    created_at = fields.DatetimeField(auto_now_add=True)

    def __str__(self):
        return self.title
