-- Берём из глобального контейнера secure нужные нам функции
local secure = ngx.shared.secure
sing_in = secure:get("sing_in")
is_secure = secure:get("is_secure")

-- Получаем ip адрес клиента
local ip = ngx.var.remote_addr

-- Получаем User-Agent адрес клиента
local ua = ngx.req.get_headers()["User-Agent"]

-- Адрес страницы аутентификации
local req_url_err = "https://auth.somedomain.ru"

-- Адрес назначения из cookie или дефолтный адрес, если в cookie адреса нет
local req_url = "https://"..(ngx.var.cookie_sv_req_url or "somedomain.ru")

-- Проверяем наличие параметров POST-запроса
ngx.req.read_body()
local args, err = ngx.req.get_post_args()
if args then
    -- 4.1. Читаем из POST-запроса логин и пароль
    local log
    local pass
    for key, val in pairs(args) do
        if key == "login" then
            log = val
        elseif key == "password" then
            pass = val
        end
    end

    -- Проверяем, что логин и пароль не пустые
    if log ~= nil and pass ~= nil then
        -- 5. Проверяем валидны ли логин и пароль
        if sing_in(log, pass) then
            -- Если валидны
            -- Задаём время жизни токена (сутки)
            local life_time = ngx.time()+86400
            -- Генерируем токен
            local auth_str = ngx.encode_base64(ngx.hmac_sha1("ОЧЕНЬ_СЕКРЕТНАЯ_ОЧЕНЬ_ДЛИННАЯ_СТРОКА_НАПРИМЕР_КАКОЙ-НИБУДЬ_32-УХЗНАЧНЫЙ_ХЭШ",ua.."|"..life_time)).."|"..life_time
            
            -- 5.1. Записываем токен в cookie и удаляем оттуда url назначения
            ngx.header["Set-Cookie"] = {"sv_auth="..auth_str.."; path=/; domain=.somedomain.ru; Expires="..ngx.cookie_time(ngx.time()+60*60*24).."; Secure; HttpOnly","sv_req_url="..ngx.req.get_headers()["Host"].."; path=/; domain=.somedomain.ru; Expires="..ngx.cookie_time(ngx.time()-60).."; Secure; HttpOnly"}
            
            -- 2.2. Возвращаем редирект на страницу назначения
            return ngx.redirect(req_url)
        end
        
        -- 5.2. Если логин/пароль невалидны, учитываем это в подсчёте неуспешных попыток аутентификации
        is_secure(ip,ua,true)
    end
end

-- 3. Если логин и пароль не переданы или невалидны, возвращаем редирект на страницу аутентификации
ngx.redirect(req_url_err)