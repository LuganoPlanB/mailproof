local ucl = require "ucl"
local P = "MAILPROOF_"
local function emit(task, symbol, record)
  local json = ucl.to_format(record, "json-compact")
  if #json > 4096 then error("projection budget exceeded") end
  task:insert_result(symbol, 0.0, json)
end
rspamd_config:register_symbol({name=P.."PROJECTION", type="postfilter", score=0.0, callback=function(task)
  local from = task:get_header_full("From") or {}
  emit(task, P.."HEADER_OBSERVATION", {schemaVersion=1, name="From", occurrences=#from})
  for _, part in ipairs(task:get_parts() or {}) do
    emit(task, P.."PART_OBSERVATION", {schemaVersion=1, id=part:get_id(), parent=part:get_parent() and part:get_parent():get_id(), digest=part:get_digest(), declared=part:get_type_full(), detected=part:get_detected_type_full(), filename=part:get_filename()})
    for _, url in ipairs(part:get_urls() or {}) do emit(task, P.."URL_OBSERVATION", {schemaVersion=1, part=part:get_id(), raw=url:get_raw(), visible=url:get_visible(), target=url:get_redirected(), flags=url:get_flags()}) end
  end
  emit(task, P.."PROJECTION_COMPLETE", {schemaVersion=1, complete=true})
  return true
end})
