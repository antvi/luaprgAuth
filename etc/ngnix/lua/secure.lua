-- Количество попыток для ip/32 и User-Agent
local ip_ua_max = 10

-- Количество попыток для ip/32
local ip_4_max = 50

-- Количество попыток для ip/16
local ip_3_max = 100

-- Количество попыток для ip/8
local ip_2_max = 500

-- Количество попыток для ip/0
local ip_1_max = 1000

counters = {}
counters["ip_ua"] = {}
counters["ip_4"] = {}
counters["ip_3"] = {}
counters["ip_2"] = {}
counters["ip_1"] = {}

-- Проверка числа попыток (is_cnt=false) и учёт неуспешной попытки (is_cnt=true)
function is_secure(ip, user_agent, is_cnt)
    local md5_ip_ua = ngx.md5(ip..user_agent)
    local md5_ip_4 = ngx.md5(ip)
    local md5_ip_3 = ""
    local md5_ip_2 = ""
    local md5_ip_1 = ""
    local cnt = 0
    for i in string.gmatch(ip, "%d+") do
        cnt = cnt + 1
        if cnt < 4 then
            md5_ip_3 = md5_ip_3.."."..i
        end
        if cnt < 3 then
            md5_ip_2 = md5_ip_2.."."..i
        end
        if cnt < 2 then
            md5_ip_1 = md5_ip_1.."."..i
        end
    end
    md5_ip_3 = ngx.md5(md5_ip_3)
    md5_ip_2 = ngx.md5(md5_ip_2)
    md5_ip_1 = ngx.md5(md5_ip_1)
    if is_cnt then
        -- Учитываем неуспешную попытку
        counters["ip_ua"][md5_ip_ua] = (counters["ip_ua"][md5_ip_ua] or 0) + 1
        counters["ip_4"][md5_ip_4] = (counters["ip_4"][md5_ip_4] or 0) + 1
        counters["ip_3"][md5_ip_3] = (counters["ip_3"][md5_ip_3] or 0) + 1
        counters["ip_2"][md5_ip_2] = (counters["ip_2"][md5_ip_2] or 0) + 1
        counters["ip_1"][md5_ip_1] = (counters["ip_1"][md5_ip_1] or 0) + 1
        
        -- Пишем в лог подробности неуспешной попытки
        log_file = io.open("/var/log/nginx/access.log", "a")
        log_file:write(ip.."	"..(counters["ip_ua"][md5_ip_ua] or 0).."	"..(counters["ip_4"][md5_ip_4] or 0).."	"..(counters["ip_3"][md5_ip_3] or 0).."	"..(counters["ip_2"][md5_ip_2] or 0).."	"..(counters["ip_1"][md5_ip_1] or 0).."	"..user_agent.."\n")
        log_file:close()
    else
        -- Проверяем число неуспешных попыток
        if
            (counters["ip_ua"][md5_ip_ua] or 0) > ip_ua_max or
            (counters["ip_4"][md5_ip_4] or 0) > ip_4_max or
            (counters["ip_3"][md5_ip_3] or 0) > ip_3_max or
            (counters["ip_2"][md5_ip_2] or 0) > ip_2_max or
            (counters["ip_1"][md5_ip_1] or 0) > ip_1_max
        then
            return false
        else
            return true
        end
    end
end

-- Проверка логина/пароля
-- В данном примере просто сравнение с хэшом из файла, при желании в данной функции можно реализовать проверку логина/пароля где угодно (в БД например)
function sing_in(log, pass)
    local auth_file = io.open("/etc/nginx/auth/pass","r")
    for line in io.lines("/etc/nginx/auth/pass") do
        if line == log..":"..ngx.md5(pass) then
            auth_file:close()
            return true
        end
    end
    auth_file:close()
    return false
end

-- Сохраняем функции в глобальном контейнере secure
local secure = ngx.shared.secure
secure:set("sing_in", sing_in)
secure:set("is_secure", is_secure)