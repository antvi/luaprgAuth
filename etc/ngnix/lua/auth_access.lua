-- Берём из глобального контейнера secure нужные нам функции
local secure = ngx.shared.secure
is_secure = secure:get("is_secure")

-- Получаем ip адрес клиента
local ip = ngx.var.remote_addr

-- Получаем User-Agent адрес клиента
local ua = ngx.req.get_headers()["User-Agent"]

-- 4. Проверка количества попыток аутентификации
if is_secure(ip,ua,false) then
    -- Проверка пройдена, удаляем невалидный токен
    ngx.header["Set-Cookie"] = {"sv_auth=; path=/; domain=.somedomain.ru; Expires="..ngx.cookie_time(ngx.time()-60).."; Secure; HttpOnly"}
    return
end

-- 4.2. Проверка не пройдена, возвращаем HTTP 403
ngx.exit(ngx.HTTP_FORBIDDEN)