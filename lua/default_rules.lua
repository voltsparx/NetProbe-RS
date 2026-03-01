-- Flow sketch: input -> processing -> output
-- Pseudo-block:
--   inspect context -> add signal -> return note

function analyze(host)
  local findings = {}
  local admin_services = { ["ssh"] = true, ["ms-wbt-server"] = true, ["telnet"] = true, ["vnc"] = true }
  local plaintext_services = { ["ftp"] = true, ["telnet"] = true, ["pop3"] = true, ["imap"] = true }
  local admin_open = 0

  for _, port in ipairs(host.ports or {}) do
    local state = port.state
    if state == "open" or state == "open_or_filtered" then
      local service = port.service
      if service and plaintext_services[service] then
        table.insert(findings, "Lua: plaintext service '" .. service .. "' exposed on port " .. tostring(port.port))
      end
      if service and admin_services[service] then
        admin_open = admin_open + 1
      end
      if port.protocol == "udp" and state == "open_or_filtered" and (port.port == 161 or port.port == 69) then
        table.insert(findings, "Lua: UDP management service might be reachable on " .. tostring(port.port))
      end
    end
  end

  if admin_open >= 2 then
    table.insert(findings, "Lua: multiple remote administration services are simultaneously exposed")
  end

  if (host.risk_score or 0) >= 70 then
    table.insert(findings, "Lua: host risk score is high; prioritize hardening and segmentation")
  end

  return findings
end


