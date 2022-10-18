from typing import Optional

import json
import hmac
import hashlib
import base64

from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response   # в респонсе хранится http ответ

app = FastAPI()  # создаёт приложение фастапи

SECRET_KEY = '744bf48be180010f2c1b65336cf209f64fe9e1c98b6ea657114f2fa50488cf21'
PASSWORD_SALT = 'a7b3f6bf205d245a0ac17beefd5257f5bf6da3c286d48b3185d2259eea6e7821'

def sign_data(data: str) -> str:
    '''Возвращает цифровую подпись из юзернейма'''
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

def get_username_from_signed_string(username_signed: str) -> Optional['str']:
    '''Если подпись правильная возвращает коректный email'''
    username_base64, sign = username_signed.split('.')
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign): # сравнивает цифровую подпись
        return username

def verify_password(username: str, password: str) -> bool:
    '''Сравнивает хэш-пароль из бд и хеш-пароль который пришёл на вход'''
    password_hash = hashlib.sha256( (password + PASSWORD_SALT).encode() ).hexdigest().lower()
    stored_password_hash = users[username]['password'].lower() # хеш пароль из нашей бд
    return password_hash == stored_password_hash 

users = {    # пользователи 
    'mrat@mail.ru' : {
        'name' : 'Игорь',
        'password' : '217eb9378e1fb03fc62eee6c0a18ae4f924b853f2bc2833206749954fa5f3577',
        'balance' : 1_000_000
    },
    'some@ya.ru' : {
        'name' : 'Арсен',
        'password' : '4640de8388aae40f1a462b1607276bf2b6230124868e26b667bb1b244582d490',
        'balance' : 10_000_000,
    }
}


@app.get('/')
def index_page(username : Optional[str] = Cookie(default=None)): # получает куки если они есть
    with open('templates/login.html', 'r') as f: # открывает шаблонм html на чтение 
        login_page = f.read()       
    if not username: # Если неправильный логин 
        return Response(login_page, media_type='text/html')
    valid_username = get_username_from_signed_string(username)
    if not valid_username: # если подпись не правильная удаляет куку
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response

    try: # если поменялось имя пользователя, то выводит на начальную страницу
        user = users[valid_username]
    except KeyError:
        response =  Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response     
    return Response(
        f"Привет, {users[valid_username]['name']} <br/>" 
        f"Баланс: {users[valid_username]['balance']}",
        media_type='text/html'
    )    


@app.post('/login')
def process_login_page(username : str = Form(...), password : str = Form(...)): # получает данные с формы
    user = users.get(username)
    if not user or not verify_password(username, password): # Проверка логина и пароля
        return Response(
            json.dumps({
                'success': False,
                'message' : 'Я вас не знаю',
            }),
            media_type='application/json')

    response =  Response(
        json.dumps({
            'success': True,
            'message': f"Привет {user['name']},<br/> Ваш баланс {user['balance']}$" 
        }), 
        media_type='application/json') # выводит после логинизации пользователя
    
    username_signed = base64.b64encode(username.encode()).decode() + '.' + sign_data(username) # делает цифровую подпись юзернейму
    response.set_cookie(key='username', value=username_signed) # устанавливает куки
    return response 









