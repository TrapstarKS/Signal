assert(getscriptbytecode, "Your exploit does not support getscriptbytecode")
assert(request, "Your exploit does not support request")
local cloneref = cloneref or function(...) return ... end
local HttpService = cloneref(game:GetService("HttpService"))

-- This is needed to work in some exploits without base64 encode (e.g. Delta)
local b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
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

local function isViableDecompileScript(scriptInstance)
	if scriptInstance:IsA("ModuleScript") then
		return true
	elseif scriptInstance:IsA("LocalScript") and (scriptInstance.RunContext == Enum.RunContext.Client or scriptInstance.RunContext == Enum.RunContext.Legacy) then
		return true
	elseif scriptInstance:IsA("Script") and scriptInstance.RunContext == Enum.RunContext.Client then
		return true
	end
	return false
end

local last_call = tick()
local oldconfig = `{getgenv().HideUpvalues or false}{getgenv().HideFunctionsNames or false}{getgenv().HideFunctionsLine or false}`
local function decompile(s)
	if typeof(s) ~= "Instance" then return `-- Failed to decompile, error:\n\n--[[\nexpected Instance, got {typeof(s)}\n--]]` end

	if not isViableDecompileScript(s) then return `-- Failed to decompile script, error:\n\n--[[\n{s} is not a viable script to decompile\n--]]` end

	local success, bytecode = pcall(getscriptbytecode, s)
	if not success then return `-- Failed to get script bytecode, error:\n\n--[[\n{bytecode}\n--]]` end

	local time_elapsed = tick() - last_call
	--if time_elapsed <= 0.5 then task.wait(0.5 - time_elapsed) end
	local hd = `{getgenv().HideUpvalues or false}{getgenv().HideFunctionsNames or false}{getgenv().HideFunctionsLine or false}`
	local response = request({
		Url = "https://starhub.dev/api/v1/decompile",
		Body = HttpService:JSONEncode({
			bytecode = enc(bytecode),
			use_cache = oldconfig == hd,
			HideUpvalues = getgenv().HideUpvalues or false,
			HideFunctionsNames = getgenv().HideFunctionsNames or false,
			HideFunctionsLine = getgenv().HideFunctionsLine or false,
		}),
		Method = "POST",
		Headers = {
			["Content-Type"] = "application/json",
		},
	})
	last_call = tick()
	oldconfig = hd
	if response.StatusCode ~= 200 then
		return `-- Error occured while requesting the API, error:\n\n--[[\n{response.Body}\n--]]`
	else
		return response.Body:gsub("\t", "    ")
	end
end

getgenv().decompile = decompile
