-- why I named this file common.lua?
local prompt = require("zeta.prompt")
local log = require("zeta.log")
local state = require("zeta.state")

local M = {}

---@class zeta.LineRange
---@field [1] integer start line number
---@field [2] integer end line number

---@class zeta.LineEdit
---@field value string[]
---@field range zeta.LineRange

---@class zeta.Prediction
---@field request_id string
---@field edits zeta.LineEdit[]

local _MAX_EVENT_TOKENS = 500
local MAX_CONTEXT_TOKENS = 150
local MAX_REWRITE_TOKENS = 350
local CURSOR_MARKER = "<|user_cursor_is_here|>"
local EDITABLE_REGION_START_MARKER = "<|editable_region_start|>"
local EDITABLE_REGION_END_MARKER = "<|editable_region_end|>"

function M.request_predict_completion()
    log.debug("request predict completion")
    local bufnr = vim.api.nvim_get_current_buf()
    -- TODO: peek all recent events instead
    local events = { state:pop_event() }
    local input_events = prompt.prompt_for_events(events)
    local excerpt = prompt.excerpt_for_cursor_position(MAX_REWRITE_TOKENS, MAX_CONTEXT_TOKENS)
    ---@type zeta.PredictEditRequestBody
    local body = {
        input_events = input_events,
        input_excerpt = excerpt.prompt,
    }
    log.debug("request body.input_events:", body.input_events)
    log.debug("request body.input_excerpt:", body.input_excerpt)
    local client = require("zeta.provider.claude")
    client.perform_predict_edit(
        body,
        vim.schedule_wrap(function(res)
            log.debug("response:", res.output_excerpt)
            local editable_range = excerpt.editable_range
            local current_editable_lines =
                vim.api.nvim_buf_get_lines(bufnr, editable_range[1] - 1, editable_range[2], false)
            -- FIX: what if file is modified right after the request..?
            -- TODO: compare lines before and after the request,
            -- if lines are modified too much that placing edits won't work,
            -- request again with new context.
            -- to enable this, request body should be ready on textchange even if
            -- previous request is still waiting
            local output_excerpt = res.output_excerpt
                :match(vim.pesc(EDITABLE_REGION_START_MARKER) .. "\n(.*)" .. vim.pesc(EDITABLE_REGION_END_MARKER))
                :gsub(vim.pesc(CURSOR_MARKER), "")
            -- TODO: diff between contents inside "editable_region"
            -- as LLM response might include some unwanted strings
            local edits = M.compute_line_edits(
                table.concat(current_editable_lines, "\n") .. "\n",
                output_excerpt,
                editable_range[1] - 1
            )
            log.debug("edits:", edits)
            local editor = require("zeta.editor")
            -- editor.set_edits(bufnr, edits)
            editor.set_prediction(bufnr, {
                request_id = "",
                edits = edits,
            })
        end)
    )
end

---@param old string original lines
---@param new string predicted lines
---@param offset integer line offset from original text
---@return zeta.LineEdit[]
function M.compute_line_edits(old, new, offset)
    ---@type zeta.LineEdit[]
    local edits = {}
    local new_lines = vim.split(new, "\n", { plain = true })
    vim.diff(old, new, {
        on_hunk = function(start_a, count_a, start_b, count_b)
            local end_a = start_a + count_a - 1
            local end_b = start_b + count_b - 1
            ---@type zeta.LineEdit
            local edit = {
                value = vim.list_slice(new_lines, start_b, end_b),
                range = {
                    offset + start_a,
                    offset + end_a,
                },
            }
            table.insert(edits, edit)
            return 1
        end,
    })
    -- TODO: only execute vim.diff on debug mode
    log.debug("diff:", "\n" .. vim.diff(old, new))
    return edits
end

return M
