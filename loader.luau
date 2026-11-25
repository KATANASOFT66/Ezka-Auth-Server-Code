local CONFIG = {
	BASE_URL = "https://REPLACE-WITH-YOUR-WORKER.workers.dev",
	PRODUCT = "aiplay",
	KEY = "GAIPLAY-XXXX-XXXX-XXXX-XXXX",
	USER_ID = "000000000",
	HWID = "",
	SCRIPT = "aiplay",
}

local HttpService = game:GetService("HttpService")
local env = getfenv and getfenv() or {}
local loadChunk = loadstring or env.loadstring

local function httpRequest(url, method, headers, body)
	local executorRequest = (syn and syn.request)
		or request
		or http_request
		or httprequest
		or (flux and flux.request)
		or env.request

	if type(executorRequest) == "function" then
		local ok, response = pcall(executorRequest, {
			Url = url,
			Method = method,
			Headers = headers,
			Body = body,
		})
		if not ok then
			return nil, tostring(response)
		end
		return response
	end

	if method == "GET" then
		local ok, result = pcall(function()
			return HttpService:GetAsync(url)
		end)
		if not ok then
			return nil, tostring(result)
		end
		return { StatusCode = 200, Body = result }
	end

	local ok, result = pcall(function()
		return HttpService:PostAsync(url, body or "", Enum.HttpContentType.ApplicationJson, false, headers)
	end)
	if not ok then
		return nil, tostring(result)
	end
	return { StatusCode = 200, Body = result }
end

local function statusOf(response)
	if type(response) ~= "table" then
		return 0
	end
	return tonumber(response.StatusCode or response.status_code or response.Status or 0) or 0
end

local function bodyOf(response)
	if type(response) ~= "table" then
		return tostring(response)
	end
	return response.Body or response.body or response.Content or ""
end

local function decodeJson(text)
	local ok, result = pcall(function()
		return HttpService:JSONDecode(text)
	end)
	if not ok then
		return nil, tostring(result)
	end
	return result
end

local function encodeQuery(values)
	local parts = {}
	for key, value in pairs(values) do
		parts[#parts + 1] = HttpService:UrlEncode(key) .. "=" .. HttpService:UrlEncode(tostring(value))
	end
	table.sort(parts)
	return table.concat(parts, "&")
end

local function getHwid()
	if type(CONFIG.HWID) == "string" and CONFIG.HWID ~= "" then
		return CONFIG.HWID
	end

	local ok, clientId = pcall(function()
		return game:GetService("RbxAnalyticsService"):GetClientId()
	end)
	if ok and type(clientId) == "string" and clientId ~= "" then
		return clientId
	end

	local executorHwid = env.HWID or (syn and syn.get_hwid) or (getgenv and getgenv().HWID)
	if type(executorHwid) == "function" then
		local callOk, value = pcall(executorHwid)
		if callOk and type(value) == "string" then
			return value
		end
	elseif type(executorHwid) == "string" then
		return executorHwid
	end

	return ""
end

local function verify()
	local userId = tostring(CONFIG.USER_ID)
	local hwid = getHwid()
	local payload = HttpService:JSONEncode({
		product = CONFIG.PRODUCT,
		key = CONFIG.KEY,
		userId = userId,
		hwid = hwid,
		nonce = HttpService:GenerateGUID(false),
	})

	local response, err = httpRequest(CONFIG.BASE_URL .. "/v1/verify", "POST", {
		["Content-Type"] = "application/json",
		Accept = "application/json",
	}, payload)

	if not response then
		local query = encodeQuery({
			product = CONFIG.PRODUCT,
			key = CONFIG.KEY,
			userId = userId,
			hwid = hwid,
		})
		response, err = httpRequest(CONFIG.BASE_URL .. "/v1/verify?" .. query, "GET", {
			Accept = "application/json",
		}, nil)
		if not response then
			return nil, err
		end
	end

	local status = statusOf(response)
	if status ~= 200 then
		return nil, "http_" .. tostring(status)
	end

	local data = decodeJson(bodyOf(response))
	if not data or data.ok ~= true or type(data.token) ~= "string" then
		if type(data) == "table" and type(data.reason) == "string" then
			return nil, data.reason
		end
		return nil, "invalid_response"
	end

	return data
end

local function loadSource(license)
	local query = encodeQuery({
		token = license.token,
		product = CONFIG.PRODUCT,
		userId = tostring(CONFIG.USER_ID),
		hwid = getHwid(),
		name = CONFIG.SCRIPT,
	})

	local response, err = httpRequest(CONFIG.BASE_URL .. "/v1/script?" .. query, "GET", {
		Accept = "application/json",
	}, nil)
	if not response then
		return nil, err
	end

	local status = statusOf(response)
	if status ~= 200 then
		return nil, "http_" .. tostring(status)
	end

	local data = decodeJson(bodyOf(response))
	if not data or data.ok ~= true or type(data.source) ~= "string" then
		if type(data) == "table" and type(data.reason) == "string" then
			return nil, data.reason
		end
		return nil, "invalid_response"
	end

	return data.source
end

local function run()
	if type(loadChunk) ~= "function" then
		return false, "loadstring_unavailable"
	end

	local license, verifyError = verify()
	if not license then
		return false, verifyError
	end

	local source, sourceError = loadSource(license)
	if not source then
		return false, sourceError
	end

	local chunk, compileError = loadChunk(source)
	if not chunk then
		return false, "compile_error: " .. tostring(compileError)
	end

	local ok, result = pcall(chunk)
	if not ok then
		return false, "runtime_error: " .. tostring(result)
	end

	return true, result
end

local ok, result = run()
if not ok then
	local output = warn or print
	output("[G.AIPLAY] " .. tostring(result))
end

return {
	run = run,
	verify = verify,
	loadSource = loadSource,
	getHwid = getHwid,
	config = CONFIG,
}
