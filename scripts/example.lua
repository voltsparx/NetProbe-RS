-- Flow sketch: input -> processing -> output
-- Pseudo-block:
--   inspect context -> add signal -> return note
-- example script keeps it tiny so customization feels approachable.

function analyze(host)
  local findings = {}
  for _, port in ipairs(host.ports or {}) do
    if (port.state == "open" or port.state == "open_or_filtered") and port.port == 443 then
      table.insert(findings, "custom: HTTPS exposed on 443, validate certificate and TLS policy")
    end
  end
  return findings
end


