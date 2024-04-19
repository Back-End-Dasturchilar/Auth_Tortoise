# Project codes' description

```shell
from fastapi import FastAPI, Depends
from fastapi.responses import Response
from typing import List
from tortoise.contrib.fastapi import register_tortoise
from utils import create_access_token, get_current_user
from models import User, Category, Blog
from schemas import UserGet, CategoryGet, BlogGet, BlogPost, CategoryPost, BlogUpdate, CategoryUpdate, Register, \
    Login, ChangePassword

app = FastAPI()


@app.post("/register", status_code=201)
async def create_user(data: Register):
    if data.password != data.password2:
        return {"message": "Пароли не совпадают"}
    del data.password2
    user = await User.create(**data.dict())
    token = await create_access_token(user)
    data = UserGet(**user.__dict__).dict()
    data["access_token"] = token
    return data


@app.post("/login")
async def login(data: Login):
    user = await User.get_or_none(username=data.username)
    if not user:
        return {'message': 'Неверное имя пользователя'}
    if data.password != user.password:
        return {'message': 'Неверный пароль'}
    token = await create_access_token(user)
    return {'access_token': token}


@app.patch("/change-password")
async def change_password(data: ChangePassword, user: User = Depends(get_current_user)):
    if data.password != data.password2:
        return {"message": "Пароли не совпадают"}
    user.password = data.password
    await user.save()
    return {'message': 'Пароль успешно обновлен'}


@app.get('/user', response_model=UserGet)
async def get_user(user: User = Depends(get_current_user)):
    return user


@app.delete("/user", status_code=204)
async def delete_user(user: User = Depends(get_current_user)):
    await user.delete()
    return {'message': 'Пользователь удалил'}


@app.post('/category', status_code=201)
async def create_category(data: CategoryPost):
    category = await Category.create(**data.dict())
    data = CategoryGet(**category.__dict__).dict()
    return data


@app.patch('/category/{pk}', response_model=CategoryGet)
async def category_update(pk: int, data: CategoryUpdate):
    data_dict = {k: v for k, v in data.dict().items() if v is not None}
    category = await Category.get_or_none(id=pk)
    if category:
        await category.update_from_dict(data_dict)
        await category.save()
        return category
    else:
        return Response({'success': False, 'message': 'Category not found'}, status_code=404)


@app.delete('/category/{pk}', status_code=204)
async def delete_category(pk: int):
    category = await Category.get_or_none(id=pk)
    if category:
        await category.delete()
        return {'success': True}
    else:
        return Response({'success': False, 'message': 'Category not found'}, status_code=404)


@app.post("/blog", status_code=201)
async def create_blog(data: BlogPost):
    data = data.dict()
    category = await Category.get_or_none(id=data['category'])
    data['category'] = category
    blog = await Blog.create(**data)
    data = BlogGet(**blog.__dict__).dict()
    return data


@app.get('/blog', response_model=List[BlogGet])
async def get_blog():
    blogs = await Blog.all()
    return blogs


@app.patch('/blog/{pk}', response_model=BlogGet)
async def income_update(pk: int, data: BlogUpdate):
    data_dict = {k: v for k, v in data.dict().items() if v is not None}
    blog = await Blog.get_or_none(id=pk)
    if blog:
        await blog.update_from_dict(data_dict)
        await blog.save()
        return blog
    else:
        return Response({'success': False, 'message': 'Blog not found'}, status_code=404)


@app.delete('/blog/{pk}', status_code=204)
async def delete_income(pk: int):
    blog = await Blog.get_or_none(id=pk)
    if blog:
        await blog.delete()
        return {'success': True}
    else:
        return Response({'success': False, 'message': 'Blog not found'}, status_code=404)


TORTOISE_ORM = {
    "connections": {
        "default": "sqlite://db.sqlite3",
    },
    "apps": {
        "models": {
            "models": ['aerich.models', 'models'],
            "default_connection": "default",
        },
    },
}
register_tortoise(
    app,
    config=TORTOISE_ORM,
    generate_schemas=True,
    add_exception_handlers=True
)

```

1. Importlar va FastAPI obyekti:
   from fastapi import FastAPI, Depends - FastAPI kutubxonasidan FastAPI va Depends klasslarini import qilish.
   from fastapi.responses import Response - FastAPI kutubxonasidan Response klassini import qilish.
   from typing import List - Python typing modulidan List tipini import qilish.
   from tortoise.contrib.fastapi import register_tortoise - Tortoise ORM kutubxonasining FastAPI uchun qo'llanma
   modulidan
   register_tortoise funktsiyasini import qilish.
   from utils import create_access_token, get_current_user - utils modulidan create_access_token va get_current_user
   funksiyalarini import qilish.
   from models import User, Category, Blog - models modulidan User, Category, va Blog klasslarini import qilish.
   from schemas import ... - schemas modulidan turli modellar va DTO obyektlarini import qilish.

2. FastAPI endpointlari:
   /register - Foydalanuvchi ro'yxatdan o'tkazish uchun POST so'rovini qabul qiladi.
   /login - Foydalanuvchi kirish uchun POST so'rovini qabul qiladi.
   /change-password - Foydalanuvchi parolni o'zgartirish uchun PATCH so'rovini qabul qiladi.
   /user - Foydalanuvchi ma'lumotlarini ko'rish uchun GET so'rovini qabul qiladi.
   /user - Foydalanuvchi ma'lumotlarini o'chirish uchun DELETE so'rovini qabul qiladi.
   /category - Kategoriya yaratish uchun POST so'rovini qabul qiladi.
   /category/{pk} - Kategoriya ma'lumotlarini o'zgartirish uchun PATCH so'rovini qabul qiladi.
   /category/{pk} - Kategoriya ma'lumotlarini o'chirish uchun DELETE so'rovini qabul qiladi.
   /blog - Blog yaratish uchun POST so'rovini qabul qiladi.
   /blog - Barcha bloglar ma'lumotlarini ko'rish uchun GET so'rovini qabul qiladi.
   /blog/{pk} - Blog ma'lumotlarini o'zgartirish uchun PATCH so'rovini qabul qiladi.
   /blog/{pk} - Blog ma'lumotlarini o'chirish uchun DELETE so'rovini qabul qiladi.

3. Tortoise ORM:
   TORTOISE_ORM o'zgaruvchisida Tortoise ORM konfiguratsiyasi aniqlangan. Bu konfiguratsiya fayl bazasi bilan bog'liq
   bo'
   lgan sozlamalarni o'z ichiga oladi.
   register_tortoise funktsiyasi esa FastAPI ilova obyektini Tortoise ORM bilan bog'lab qo'yadi.

4. Funksiyalar va ma'lumotlar bilan ishlash:
   create_user, login, change_password, get_user, delete_user, create_category, category_update, delete_category,
   create_blog, get_blog, income_update, va delete_income funksiyalari har bir endpoint uchun muvofiqliyatini
   ta'minlaydi.
   Ma'lumotlar bazasi bilan o'zaro amallar (qo'shish, o'zgartirish, o'chirish) ham shular orqali amalga oshiriladi.
   Ba'zi funksiyalar shartlarga qarab ishlaydi (masalan, parolni tekshirish, obyekt topish, ma'lumotlarni yangilash va
   o'
   chirish).

```shell
from jose import jwt, JWTError
from models import User
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException
from fastapi.security.http import HTTPBearer

SECRET_KEY = 'secret_key'
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30


async def create_access_token(user: User) -> str:
    data = {'id': user.id}
    expire = datetime.now().astimezone() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data['exp'] = expire
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(HTTPBearer())):
    token = token.__dict__
    try:
        payload = jwt.decode(token['credentials'], SECRET_KEY, algorithms=[ALGORITHM])
        user = await User.get_or_none(id=payload['id'])
        if not user:
            raise HTTPException(status_code=403, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail='Could not validate credentials',
                            headers={'WWW-Authenticate': 'Bearer'})

```

Bu kodlar JWT (JSON Web Token) yaratish va tekshirish funktsiyalarini o'z ichiga oladi, bu esa foydalanuvchini
identifikatsiya qilish uchun ishlatiladi. Kodni qatorlarini ta'riflash kerak:

1. from jose import jwt, JWTError: Bu qator JSON Web Token (JWT) yaratish va tekshirish uchun jwt modulini import
   qiladi,
   shuningdek, JWTError nomli istisnolarni.

2. from models import User: Bu qator, foydalanuvchini (User) ma'lumotlar bazasidan ishlatish uchun User klassini import
   qiladi.

3. from datetime import datetime, timedelta: Bu qator, vakti hisoblash vaqtini (datetime) va vaqt intervalini (
   timedelta)
   ishlatish uchun ilovalangan modullarni import qiladi.

4. from fastapi import Depends, HTTPException: Bu qator FastAPI bilan ishlaydigan modullarni import qiladi. Depends
   asosiy
   funksiyalar uchun dependency injektsiyasini o'z ichiga oladi, HTTPException esa HTTP islohotlari (HTTP status kodlari
   va
   xatolik xabarlari) yaratish uchun ishlatiladi.

5. from fastapi.security.http import HTTPBearer: Bu qator FastAPI modulidan HTTP Bearer avtorizatsiya turini import
   qiladi.

6. SECRET_KEY = 'secret_key': Bu qator, JWT yaratishda ishlatiladigan maxfiy kalitni (SECRET_KEY) o'zgaruvchisini
   aniqlaydi.

7. ALGORITHM = 'HS256': Bu qator, JWT yaratishda ishlatiladigan algoritmni (ALGORITHM) aniqlaydi.

8. ACCESS_TOKEN_EXPIRE_MINUTES = 30: Bu qator, yaratilgan JWT tokenlarining amal qilish muddatini (daqiqalarda)
   aniqlaydi.

9. async def create_access_token(user: User) -> str:: Bu qator, foydalanuvchining (User) ma'lumotlaridan foydalanib, JWT
   token yaratish uchun asinxron funktsiyani aniqlaydi. Funktsiya SECRET_KEY va ALGORITHM orqali token yaratadi va uning
   amal qilish muddatini ACCESS_TOKEN_EXPIRE_MINUTES orqali aniqlaydi.

10. async def get_current_user(token: str = Depends(HTTPBearer())):: Bu qator, foydalanuvchini identifikatsiya qilish
    uchun
    asinxron get_current_user funktsiyasini aniqlaydi. Funktsiya HTTP Bearer autentifikatsiya turi orqali token qabul
    qiladi
    va uning ishchi malumotlarini (payload) tekshiradi. Agar token muvaffaqiyatli tasdiqlanmasa, HTTP xatolik (
    HTTPException) yaratiladi.
    Kodni barcha qatorlarini ko'rib chiqish orqali, uning asosiy maqsadini tushunishingiz mumkin bo'lishi kerak:
    foydalanuvchilarni autentifikatsiya qilish va ularga ma'lumotlar bazasidan murojaat qilish.