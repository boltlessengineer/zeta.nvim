local log = require("zeta.log")
local curl = require("plenary.curl")

local M = {}

local CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
local CLAUDE_API_TOKEN = vim.env.CLAUDE_API_TOKEN
local SYSTEM_PROMPT_PATH = vim.api.nvim_get_runtime_file("prompt/claude/system-prompt.md", false)[1]
local USER_PROMPT_PATH = vim.api.nvim_get_runtime_file("prompt/claude/user-prompt.md", false)[1]

---@param body zeta.PredictEditRequestBody
---@param callback fun(res: zeta.PredictEditResponse)
function M.perform_predict_edit(body, callback)
    local system_prompt = (function()
        local file = assert(io.open(SYSTEM_PROMPT_PATH))
        local content = file:read("*a")
        file:close()
        return content
    end)()
    local user_prompt_template = (function()
        local file = assert(io.open(USER_PROMPT_PATH))
        local content = file:read("*a")
        file:close()
        return content
    end)()
    local user_prompt = user_prompt_template
        :gsub("<events>", body.input_events)
        :gsub("<excerpt>", body.input_excerpt)
    local req_body = {
        model="claude-3-5-haiku-20241022",
        max_tokens=1000,
        temperature=0,
        system = system_prompt,
        messages = {
            {
                role = "user",
                content = {
                    { type = "text", text = user_prompt },
                },
            },
            {
                role = "assistant",
                content = {
                    { type = "text", text = "### Predicted Excerpt:\n\nHere is a modified excerpt including users predicted next edits." },
                },
            },
        },
    }
    log.debug("claude request body:", req_body)
    curl.post(CLAUDE_API_URL, {
        body = vim.json.encode(req_body),
        headers = {
            ["Content-Type"] = "application/json",
            ["x-api-key"] = CLAUDE_API_TOKEN,
            ["anthropic-version"] = "2023-06-01",
        },
        callback = function(resp)
            if resp.status ~= 200 then
                log.debug("request failed:", resp)
                return
            end
            local _ok, resp_body = pcall(vim.json.decode, resp.body)
            -- TODO: validate resp_body signature
            callback({
                request_id = "",
                output_excerpt = resp_body.content[1].text,
            })
        end
    })
end

return M
