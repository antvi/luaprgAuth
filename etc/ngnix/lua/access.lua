-- Адрес страницы аутентификации
local req_url_err = "https://auth.domain.ru"

-- Получаем User-Agent адрес клиента
local ua = ngx.req.get_headers()["User-Agent"]

-- Получаем токен и время из cookie
local auth_str = ngx.var.cookie_sv_auth
local auth_token = ""
local life_time = ""

if auth_str ~= nil and auth_str:find("|") ~= nil then
    local divider = auth_str:find("|")
    auth_token = auth_str:sub(0,divider-1)
    life_time = auth_str:sub(divider+1)

    -- 2. Проверяем валидность токена
    if auth_token == ngx.encode_base64(ngx.hmac_sha1("ОЧЕНЬ_СЕКРЕТНАЯ_ОЧЕНЬ_ДЛИННАЯ_СТРОКА_НАПРИМЕР_КАКОЙ-НИБУДЬ_32-УХЗНАЧНЫЙ_ХЭШ",ua.."|"..life_time)) and tonumber(life_time) >= ngx.time() then
        -- Токен валиден
        return
    end
end

-- Токен не валиден или отсутствует
-- 2.1. Сохраняем в coockie url назначения
ngx.header["Set-Cookie"] = "sv_req_url="..ngx.req.get_headers()["Host"].."; path=/; domain=.domain.ru; Expires="..ngx.cookie_time(ngx.time()+60*60).."; Secure; HttpOnly"

-- И возвращаем редирект на страницу аутентификации
return ngx.redirect(req_url_err)