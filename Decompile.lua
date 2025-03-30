assert(getscriptbytecode, "Your exploit does not support getscriptbytecode")
assert(request, "Your exploit does not support request")
local cloneref = cloneref or function(...) return ... end
local HttpService = cloneref(game:GetService("HttpService"))

-- This is needed to work in some exploits without base64 encode (e.g. Delta)
local b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
--stylua: ignore
local function enc(data)
	return ((data:gsub('.', function(x) 
        local r,b='',x:byte()
        for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
        return r;
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c=0
        for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
        return b:sub(c+1,c+1)
    end)..({ '', '==', '=' })[#data%3+1])
end
--stylua: ignore
function dec(data)
	data = string.gsub(data, '[^'..b..'=]', '')
    return (data:gsub('.', function(x)
        if (x == '=') then return '' end
        local r,f='',(b:find(x)-1)
        for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
        return r;
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then return '' end
        local c=0
        for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end
        return string.char(c)
    end))
end

local function isViableDecompileScript(scriptInstance)
	if scriptInstance:IsA("ModuleScript") then
		return true
	elseif scriptInstance:IsA("LocalScript") then
		return (scriptInstance.RunContext == Enum.RunContext.Client or scriptInstance.RunContext == Enum.RunContext.Legacy)
	elseif scriptInstance:IsA("Script") then
		return scriptInstance.RunContext == Enum.RunContext.Client
	end
	return false
end

local function getCurrentConfig() return string.format("%s%s%s", tostring(getgenv().HideUpvalues or false), tostring(getgenv().HideFunctionsNames or false), tostring(getgenv().HideFunctionsLine or false)) end

--local last_call = tick()
local lastConfig = getCurrentConfig()
local function decompile(s)
	local typeof_s = typeof(s)
	if typeof_s ~= "Instance" and typeof_s ~= "string" and typeof_s ~= "function" then return `-- Failed to decompile script, error:\n\n--[[\nexpected Instance, string or Function, got {typeof_s}\n--]]` end

	if typeof_s == "function" then
		local success, r = pcall(getfenv, s)
		if not success then return `-- Failed to decompile script, error:\n\n--[[\n{r}\n--]]` end
		if not r or not r.script then return `-- Failed to decompile script, error:\n\n--[[\n{r} is not a viable script to decompile\n--]]` end
		s = r.script
		if typeof(s) ~= "Instance" then return `-- Failed to decompile script, error:\n\n--[[\ngetfenv(func).script returned {typeof(s)}, expected Instance\n--]]` end
	end

	if (typeof_s ~= "string") and not isViableDecompileScript(s) then return `-- Failed to decompile script, error:\n\n--[[\n{s} is not a viable script to decompile\n--]]` end

	local success, bytecode = pcall(getscriptbytecode, s)
	if not success then
		if typeof_s == "string" then
			success = true
			bytecode = (utf8.len(s) or 0) > 0 and dec(s) or s
		else
			return `-- Failed to get script bytecode, error:\n\n--[[\n{bytecode}\n--]]`
		end
	end
	if not bytecode then return `-- Failed to get script bytecode, error:\n\n--[[\nbytecode is nil\n--]]` end

	--local time_elapsed = tick() - last_call
	--if time_elapsed <= 0.5 then task.wait(0.5 - time_elapsed) end
	local currentConfig = getCurrentConfig()
	local response = request({
		Url = "https://starhub.dev/api/v1/decompile",
		Body = HttpService:JSONEncode({
			bytecode = enc(bytecode),
			use_cache = (lastConfig == currentConfig),
			HideUpvalues = getgenv().HideUpvalues or false,
			HideFunctionsNames = getgenv().HideFunctionsNames or false,
			HideFunctionsLine = getgenv().HideFunctionsLine or false,
		}),
		Method = "POST",
		Headers = {
			["Content-Type"] = "application/json",
		},
	})
	--last_call = tick()
	lastConfig = currentConfig
	if response.StatusCode ~= 200 then
		return `-- Error occured while requesting the API, error:\n\n--[[\n{response.Body}\n--]]`
	else
		local t = response.Body:gsub("\t", "    ")
		if typeof_s == "function" then t = "--Script: " .. tostring(s:GetFullName()) .. "\n" .. t end
		return t
	end
end

getgenv().decompile = decompile
